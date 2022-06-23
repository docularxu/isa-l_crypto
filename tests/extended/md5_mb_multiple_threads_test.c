/**********************************************************************
  Copyright(c) 2022 Linaro Ltd. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>

#include <stdlib.h>
#include <poll.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/ioctl.h>
#include <openssl/md5.h>
#include "md5_mb.h"
#include "test.h"
#include "mpscq.h"
#include "mpsc.c"

#define unlikely(x)	__builtin_expect((x), 0)
#define likely(x)	__builtin_expect((x), 1)

/* configurable MACROs */
#define ERR_PRINT	printf
// #define DBG_PRINT	printf
#define DBG_PRINT
#define DIGEST_VERIFY	/* verify the digest against OpenSSL */
// #define USING_PIPE	/* when undefined, using queue */

#define NUM_CTX_SLOTS	512	/* number of available CTX slots
				 * in the CTX_POOL */
#define CTX_FLUSH_NSEC		(10000)	/* nanoseconds before forced mb_flush */
#define CTX_FLUSH_MIN_NSEC	(100)	/* minimum ns before forced mb_flush */
#define max(a,b)		(((a) > (b)) ? (a) : (b))

#ifdef USING_PIPE
/* Inter-thread communication pipe
 *   One consumer: md5_mb_worker_thread_main
 *   Multiple producers: user threads who calls wd_digest APIs
 */
int pipefd[2];
#else /* using queue */
struct mpscq *md5_mb_worker_queue;
#endif

/* handle of md5 multibuffer work thread */
pthread_t md5_mbthread;

/* MD5_mb manager struct
 *   From a resource viewpoint, one mb manager represents one CPU core. Data
 *   lanes in one CPU core are all the computing resources a mb manager
 *   can use.
 */
MD5_HASH_CTX_MGR md5_ctx_mgr;

typedef int md5_callback_t(void *cb_param);

typedef struct {
	uint32_t	len;
	unsigned char	*buff;
	HASH_CTX_FLAG	flags;
	md5_callback_t	*cb;
	void		*cb_param;
	sem_t		sem_job_done;		/* unlocked when MD5_mb_worker thread
						 * finished processing of this CTX */
	uint64_t	len_processed;		/* total length of data which has
						 * been processed */
} MD5_CTX_USERDATA;

/* pre-allocated space for userdata[] */
MD5_CTX_USERDATA	userdata[NUM_CTX_SLOTS];

/* struct of CTX_POOL
 *   All incoming requests must get one MD5_HASH_CTX before it
 *   can be serviced
 */
struct CTX_POOL {
	sem_t		sem_ctx_filled;		/* unlocked when new CTX ready */
	MD5_HASH_CTX	ctxpool[NUM_CTX_SLOTS];
	int		inuse[NUM_CTX_SLOTS];	/* to mark the related
						   ctxpool[slot] in use (1)
						   or not (0) */
	int		cur_idx;		/* the index to start searching */
	pthread_mutex_t	mutex_a;		/* to protect inuse[] and cur_idx */
} md5_ctx_pool;

/* ctx_pool_init -- initialize a pool of MD5_HASH_CTX
 * Return:
 *    0: succeeded
 *   -1: failed
 */
static int ctx_pool_init(void)
{
	int ret = 0;

	if (sem_init(&md5_ctx_pool.sem_ctx_filled, 0, 0) == -1) {
		ERR_PRINT("sem_init .sem_ctx_filled failed\n");
		return -1;
	}

	for (int i = 0; i < NUM_CTX_SLOTS; i ++) {
		md5_ctx_pool.inuse[i] = 0;	// initialzed to not in use
		hash_ctx_init(&md5_ctx_pool.ctxpool[i]);	// Init ctx contents
		// setup .userdata pointer
		md5_ctx_pool.ctxpool[i].user_data = &userdata[i];
		// initialize semaphore
		sem_init(&userdata[i].sem_job_done, 0, 0);
	}
	md5_ctx_pool.cur_idx = 0;		// starting from 0

	if (pthread_mutex_init(&md5_ctx_pool.mutex_a, NULL) != 0) {
		ERR_PRINT("pthread_mutex_init .mutex_a failed\n");
		return -1;
	}

	return 0;	
}

/* ctx_slot_request -- request a free MD5_HASH_CTX from md5_ctx_pool
 * Return:
 *   on success, it returns the index of a free CTX slot.
 *   on failure, it returns a negative value.
 * 	-1: no free CTX slot
 */
static int ctx_slot_request(void)
{
	int ret = -1;

	pthread_mutex_lock(&md5_ctx_pool.mutex_a);
	for (int i = 0; i < NUM_CTX_SLOTS; i ++) {
		if (md5_ctx_pool.inuse[md5_ctx_pool.cur_idx] == 0) {
			md5_ctx_pool.inuse[md5_ctx_pool.cur_idx] = 1;	// update .inuse[]
			ret = md5_ctx_pool.cur_idx;			// return this slot
			md5_ctx_pool.cur_idx =				// increment .cur_idx
				(md5_ctx_pool.cur_idx + 1) % NUM_CTX_SLOTS;
			break;
		};
		md5_ctx_pool.cur_idx =				// increment .cur_idx
			(md5_ctx_pool.cur_idx + 1) % NUM_CTX_SLOTS;
	}
	pthread_mutex_unlock(&md5_ctx_pool.mutex_a);
	return ret;
}

/* ctx_slot_release -- release the designated CTX slot back to the pool
 * Input:
 *   ctx_idx: index of the CTX slot to be released
 * Return:
 *   on success, it returns 0
 *   on failure, it returns a negative value.
 */
static int ctx_slot_release(int ctx_idx)
{
	pthread_mutex_lock(&md5_ctx_pool.mutex_a);
	md5_ctx_pool.inuse[ctx_idx] = 0;	// update .inuse[]
	pthread_mutex_unlock(&md5_ctx_pool.mutex_a);

	return 0;
}

/* wd_md5_ctx_callback -- common callback function for MD5 CTX
 * Input:
 *   ctx: a pointer to a finished MD5_HASH_CTX
 * Return:
 *   on success, it returns 0
 *   on failure, it returns a negative value.
 */
static int wd_md5_ctx_callback(MD5_HASH_CTX *ctx)
{
	MD5_CTX_USERDATA *userdata = (MD5_CTX_USERDATA *)ctx->user_data;

	return sem_post(&userdata->sem_job_done);
}

typedef enum {
	TIME_FLUSH_NEVER = 0,	/* 1 hour */
	TIME_FLUSH_FIRST = 1,	/* CTX_FLUSH_NSEC */
} TIME_FLUSH_LEVEL;

/* set_time_flush -- set flush timeout */
static void set_time_flush(struct timespec *ts, TIME_FLUSH_LEVEL level)
{
	clock_gettime(CLOCK_REALTIME, ts);
	switch (level) {
	case TIME_FLUSH_NEVER:
		ts->tv_sec += (60 * 60);	/* 1 hour */
		break;
	case TIME_FLUSH_FIRST:
	default:
		ts->tv_nsec += CTX_FLUSH_NSEC;
		if (ts->tv_nsec >= 1000000000) {
			ts->tv_sec+=1;
			ts->tv_nsec-=1000000000;
		}
		break;
	}
}

/* md5_mb_worker_thread_main -- main thread of md5 multibuffer
 */
static void *md5_mb_worker_thread_main(void *args)
{
	struct timespec time_flush = { 0 };
	MD5_HASH_CTX *ctx = NULL;
	MD5_CTX_USERDATA *userdata;
	int ctx_idx;
	int ret;

	DBG_PRINT("Enter %s\n", __func__);

	set_time_flush(&time_flush, TIME_FLUSH_NEVER);
	while (1) {
		ret = sem_timedwait(&md5_ctx_pool.sem_ctx_filled, &time_flush);
		if (ret == -1 && errno == ETIMEDOUT) {	// timeout
			DBG_PRINT("sem timed out. sec=%ld, nsec=%ld ns\n", time_flush.tv_sec,
					time_flush.tv_nsec);
			// DBG_PRINT(".");
			/* TODO: should we _flush repetitively to finish all jobs,
			 *         or should we _flush only once?
			 *       If _flush only once, should we decrease time_flush
			 *         to make the next timeout come faster?
			 */
			// call _flush() on timeout
			ctx = md5_ctx_mgr_flush(&md5_ctx_mgr);

			// check if a valid *job is returned, call its _cb())
			if (ctx != NULL) {
				userdata = (MD5_CTX_USERDATA *)ctx->user_data;
				(userdata->cb)(userdata->cb_param);
				set_time_flush(&time_flush, TIME_FLUSH_FIRST);
			} else {
				// not job pending, no need to timed wait
				set_time_flush(&time_flush, TIME_FLUSH_NEVER);
			}
			continue;	// loop back for next
		}
		
		if (ret == 0) {		// new CTX coming
			// read in CTX index
#ifdef USING_PIPE
			ret = read(pipefd[0], &ctx_idx, sizeof(int));
			if (unlikely(ret <= 0))
				ERR_PRINT("Failed to read from pipe. ret=%d, errno=%d", ret, errno);
			if (unlikely(ctx_idx >= NUM_CTX_SLOTS))
				ERR_PRINT("Unexpected CTX slot index. ctx_idx=%d\n", ctx_idx);
			ctx = &md5_ctx_pool.ctxpool[ctx_idx];
			DBG_PRINT("read from pipe, length=%d bytes, ctx_idx=%d\n",
							ret, ctx_idx);
#else /* using queue */
			#if 0
			int sval;
			if (sem_getvalue(&md5_ctx_pool.sem_ctx_filled, &sval) == 0) {
				ERR_PRINT("\t\t\t\tafter sem_wait: sem_getvalue: %d \n", sval);
			}
			ERR_PRINT("\t\t\t\tQueue ncount: %zu \n", mpscq_count(md5_mb_worker_queue));
			#endif

			while (unlikely((ctx = mpscq_dequeue(md5_mb_worker_queue)) == NULL)) {
				// TODO: need to limit the times retry
				ERR_PRINT("\t\t\t\tRETRY DEQUEUE...\n");
				continue;
			};

			#if 0
			if (unlikely(q_node == NULL)) {
				ERR_PRINT("Unexpected: Empty queue. \n");
				set_time_flush(&time_flush, TIME_FLUSH_FIRST);
				continue;	// loop back for next
			}
			#endif

			/* ctx_idx = ctx - &md5_ctx_pool.ctxpool[0]; */
			// ERR_PRINT("\t\t\t\tQueue pop succeed: ctx_idx=%d \n", \
							ctx - &md5_ctx_pool.ctxpool[0]);
			// DBG_PRINT("read from pipe, length=%d bytes, ctx_idx=%d\n", \
							ret, ctx - &md5_ctx_pool.ctxpool[0]);
#endif
			userdata = (MD5_CTX_USERDATA *)ctx->user_data;

			// call _submit() on new CTX
			ctx = md5_ctx_mgr_submit(&md5_ctx_mgr, ctx, userdata->buff,
						 userdata->len, userdata->flags);

			// check if a valid *job is returned, call its _cb())
			if (ctx != NULL) {
				userdata = (MD5_CTX_USERDATA *)ctx->user_data;
				(userdata->cb)(userdata->cb_param);
			}

			set_time_flush(&time_flush, TIME_FLUSH_FIRST);
			continue;	// loop back for next
		}

		// on all other errors
		continue;
	}; // end of while
}

/**
 * @brief Allocate a CTX slot from the md5_ctx_pool and return the index
 * @return:
 *    0 or positive: succeed, return the CTX index
 *    negative: failure
 *    -EBUSY: All CTXs in the md5_ctx_pool have been used. Upper
 *              layer can try again at a later time.
 */
int wd_do_digest_init(void)
{
	int ctx_idx;
	MD5_HASH_CTX *ctx;
	MD5_CTX_USERDATA *userdata;

	// alloc a free CTX
	ctx_idx = ctx_slot_request();
	if (ctx_idx < 0)
		return -EBUSY;
	ctx = &md5_ctx_pool.ctxpool[ctx_idx];
	userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);

	//   - Init ctx contents
	hash_ctx_init(ctx);
	//   - set len_processed to 0
	userdata->len_processed = 0;
	//   - set callback params into .userdata
	userdata->cb_param = (void *)ctx;
	//   - set callback into .userdata
	userdata->cb = (md5_callback_t *)wd_md5_ctx_callback;

	return ctx_idx;
}

/**
 * @brief Interface API published to upper layers. When called,
 *     it do MD5 digest calculation in a synchronised manner.
 *
 * @param ctx_idx
 * @param buff
 * @param len
 * @return
 *    0: succeeded
 *    negative: failure
 */
int wd_do_digest_sync(int ctx_idx, unsigned char *buff, uint32_t len)
{

	MD5_HASH_CTX *ctx;
	MD5_CTX_USERDATA *userdata;

	ctx = &md5_ctx_pool.ctxpool[ctx_idx];
	userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);

	//   - according to len_processed to set flags
	if (userdata->len_processed == 0)
		userdata->flags = HASH_FIRST;
	else if (len == 0)
		userdata->flags = HASH_LAST;
	else
		userdata->flags = HASH_UPDATE;

	//   - set *buff and len into .userdata
	userdata->buff = buff;
	userdata->len = len;

#ifdef USING_PIPE
	// write 'ctx_idx' into pipe
	write(pipefd[1], &ctx_idx, sizeof(ctx_idx));
#else /* using queue */
	bool ret;
	ret = mpscq_enqueue(md5_mb_worker_queue, ctx);
	if (unlikely(ret == false)) {
		ERR_PRINT("unexpeced, queue is full\n");
		return -1;
	}
	// ERR_PRINT("Queue push: ctx_idx=%d\n", ctx_idx);
#endif
	// notify MD5 mb worker thread
	sem_post(&md5_ctx_pool.sem_ctx_filled);

	// waiting on sem_job_done, ->cb() will unlock it when the job is done
	sem_wait(&userdata->sem_job_done);

	// update the len_processed
	userdata->len_processed += len;
	return 0;
}

/**
 * @brief retrieve the digest value and free the CTX slot
 *
 * @param ctx_idx
 * @param digest
 * @return
 *    0: succeeded
 *    negative: failure
 */
#ifdef DIGEST_VERIFY
int wd_do_digest_final(int ctx_idx, unsigned char *digest, unsigned char *md5_ssl)
#else
int wd_do_digest_final(int ctx_idx, unsigned char *digest)
#endif
{
	MD5_HASH_CTX *ctx;

	ctx = &md5_ctx_pool.ctxpool[ctx_idx];

	/* finalize this CTX */
	wd_do_digest_sync(ctx_idx, NULL, 0);

	memcpy(digest, hash_ctx_digest(ctx), MD5_DIGEST_LENGTH);

#ifdef DIGEST_VERIFY
	for (int j = 0; j < MD5_DIGEST_NWORDS; j++) {
		if (ctx->job.result_digest[j] != to_le32(((uint32_t *)md5_ssl)[j])) {
			ERR_PRINT("\n================= DIGEST_FAILURE %08X <=> %08X\n",
				ctx->job.result_digest[j],
				to_le32(((uint32_t *) md5_ssl)[j]));
		}
	}
#endif

	ctx_slot_release(ctx_idx);
	return 0;
}

/* md5_mb_bind_fn -- binding function of MD5 multibuffer lib
 * Return:
 *    0: succeeded
 *   -1: failed
 */
int md5_mb_bind_fn(void)
{
	int ret = 0;
	
	/* step 1: create an entity for communitcations */
#ifdef USING_PIPE
	if (pipe2(pipefd, O_DIRECT) != 0) {
		ERR_PRINT("pipe creation failed\n");
		return -1;
	}
#else /* using queue */
	md5_mb_worker_queue = mpscq_create(NULL, NUM_CTX_SLOTS);
#endif

	/* step 1.1: initialize CTX pool */
	if (ctx_pool_init() !=0) { ERR_PRINT("ctx_pool_init() failed\n");
		// TODO: tear down the pipe
		return -1;
	}

	/* step 2: initialize mb mgr */
	md5_ctx_mgr_init(&md5_ctx_mgr);

	/* step 3: create md5_mb worker thread */
	ret = pthread_create(&md5_mbthread, NULL,
			     &md5_mb_worker_thread_main, (void *)NULL);
	if (ret != 0)
		ERR_PRINT("md5_mb worker thread pthread_create() failed\n");

	return ret;
}

/* test stub */
#define TEST_BUFS 1024

#ifdef CACHED_TEST
// Loop many times over same data
#  define TEST_LEN     4*1024
#  define TEST_LOOPS   10000
#  define TEST_TYPE_STR "_warm"
#else
// Uncached test.  Pull from large mem base.
#  define GT_L3_CACHE  320*1024*1024	/* some number > last level cache */
#  define TEST_LEN     (GT_L3_CACHE / TEST_BUFS)
#  define TEST_LOOPS   100
#  define TEST_TYPE_STR "_cold"
#endif

unsigned char *bufs[TEST_BUFS];		/* each bufs has a length of (TEST_LEN+offset) bytes */
/* Reference digest global to reduce stack usage */
static uint8_t digest_ssl[TEST_BUFS][MD5_DIGEST_LENGTH];

#define NUM_PRODUCERS (TEST_BUFS)
pthread_t producer_threads[NUM_PRODUCERS];

#if NUM_RODUCERS > TEST_BUFS
#error "wrong producer number configurations"
#endif

pthread_mutex_t	mutex_counting;
pthread_cond_t cond_jobs_completed;
int finished_jobs_counts;

/* producer_thread_func */
static void *producer_thread_func(void *args)
{
	unsigned char digest[MD5_DIGEST_LENGTH];
	unsigned char **buf;
	int buf_offset;		// buf offset, which determines the buf length
	int loops = TEST_LOOPS;	// how many loops to run
	int ctx_idx;
	int ret;

	buf = (unsigned char **)args;
	buf_offset = buf - bufs;

	/* submit a md5 request */
	while (loops) {
		ctx_idx = wd_do_digest_init();
		if (unlikely(ctx_idx == -EBUSY)) {
			usleep(100);
			continue;
		}

#if 0	/* check the number of unread bytes in pipe */
#ifdef USING_PIPE
	int nbytes;
	ioctl(pipefd[1], FIONREAD, &nbytes);
	if (unlikely(nbytes >= 0))
		ERR_PRINT("UNREAD bytes in PIPE: %d\n", nbytes);
#endif
#endif

		wd_do_digest_sync(ctx_idx, *buf, TEST_LEN + buf_offset);
#ifdef DIGEST_VERIFY
		wd_do_digest_final(ctx_idx, digest, digest_ssl[buf_offset]);
#else
		wd_do_digest_final(ctx_idx, digest);
#endif
		loops --;
	}

	pthread_mutex_lock(&mutex_counting);
	finished_jobs_counts ++;
	if (finished_jobs_counts == NUM_PRODUCERS)
		pthread_cond_signal(&cond_jobs_completed);
	pthread_mutex_unlock(&mutex_counting);

	DBG_PRINT("Buf_Offset: %d Done! Total finished jobs: %d\n", buf_offset, finished_jobs_counts);
	return NULL;
}

// Generates pseudo-random data
static void rand_buffer(unsigned char *buf, const long buffer_size)
{
	long i;
	for (i = 0; i < buffer_size; i++)
		buf[i] = rand();
}

/* main -- main funciton of test stub
 * Return:
 *   -1: failure
 */
int main(void)
{
	struct perf start_ssl, stop_ssl;	/* OpenSSL reference */
	struct perf start, stop;		/* this implementation */
	int ret;

	/* create test buffers */
	for (int i = 0; i < TEST_BUFS; i++) {
		// each bufs[] has a different length
		bufs[i] = (unsigned char *)calloc((size_t)TEST_LEN + i, 1);
		if (bufs[i] == NULL) {
			ERR_PRINT("calloc failed test aborted\n");
			return -1;
		}
		rand_buffer(bufs[i], TEST_LEN + i);
	}

#ifdef DIGEST_VERIFY
	// Start OpenSSL tests
	printf("OpenSSL_ref" TEST_TYPE_STR "\t: ");
	/* perf start */
	perf_start(&start_ssl);
	for(int j = 0; j < TEST_LOOPS; j++)
		for (int i = 0; i < TEST_BUFS; i++)
			MD5(bufs[i], TEST_LEN + i, digest_ssl[i]);
	/* perf stop */
	perf_stop(&stop_ssl);

	/* print performance: bandwidth */
	perf_print(stop_ssl, start_ssl,
			(long long) TEST_LOOPS * 
			(TEST_LEN + TEST_LEN + TEST_BUFS) *
			NUM_PRODUCERS / 2);	/* LENGTH */
#endif

	/* create md5_mb worker thread */
	printf("multibinary_md5" TEST_TYPE_STR "\t: ");
	md5_mb_bind_fn();
	DBG_PRINT("created md5_mb_worker_thread\n");

	/* init jobs syncs mutex and cond */
	if (pthread_cond_init(&cond_jobs_completed, NULL) != 0) {
		ERR_PRINT("init cond_jobs_completed failed\n");
		return -1;
	}
	if (pthread_mutex_init(&mutex_counting, NULL) != 0) {
		ERR_PRINT("init mutex_counting init failed\n");
		return -1;
	}
	finished_jobs_counts = 0;

	/* perf start */
	perf_start(&start);

	/* start producers */
	for (int i = 0; i < NUM_PRODUCERS; i ++) {
		ret = pthread_create(&producer_threads[i], NULL,
					&producer_thread_func, (void *)&bufs[i]);
		if (ret != 0)
			ERR_PRINT("producer pthread_create() failed\n");
	}

	/* waiting until all jobs finished */
	pthread_mutex_lock(&mutex_counting);
	pthread_cond_wait(&cond_jobs_completed, &mutex_counting);
	pthread_mutex_unlock(&mutex_counting);

	/* perf stop */
	perf_stop(&stop);

	perf_print(stop, start,
			(long long) TEST_LOOPS *
			(TEST_LEN + TEST_LEN + NUM_PRODUCERS) *
			NUM_PRODUCERS / 2);	/* LENGTH */

	printf("Multi-buffer md5 test complete %d PRODUCERS of %d BYTES with "
	       "%d LOOPS\n", NUM_PRODUCERS, TEST_LEN, TEST_LOOPS);

	for (int i = 0; i < TEST_BUFS; i++) {
		free(bufs[i]);
	}

	/* on hold */
	pthread_cancel(md5_mbthread);

#ifndef USING_PIPE
	/* clear queue */
	mpscq_destroy(md5_mb_worker_queue);
#endif
	return 0;
}