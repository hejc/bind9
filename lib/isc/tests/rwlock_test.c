/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#if HAVE_CMOCKA

#include <fcntl.h>
#include <sched.h> /* IWYU pragma: keep */
#include <semaphore.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/file.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/pause.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/stdio.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/util.h>

#include "isctest.h"
#include "rwlock_p.h"

#define LOOPS	   100000
#define DELAY_LOOP 1

static unsigned int workers = 0;
static isc_rwlock_t rwlock;
static pthread_rwlock_t prwlock;

static sem_t sem1;
static sem_t sem2;

#define ITERS 20

#define DC	200
#define CNT_MIN 800
#define CNT_MAX 1600

static size_t shared_counter = 0;
static size_t expected_counter = SIZE_MAX;
static uint8_t boundary = 0;
static uint8_t rnd[LOOPS];

static bool skip_long_tests = false;
#define SKIP_IN_CI             \
	if (skip_long_tests) { \
		skip();        \
		return;        \
	}

static int
_setup(void **state) {
	isc_result_t result;
	char *p;

	if (workers == 0) {
		workers = isc_os_ncpus();
	}

	p = getenv("ISC_TASK_WORKERS");
	if (p != NULL) {
		workers = atoi(p);
	}
	INSIST(workers != 0);

	UNUSED(state);

	result = isc_test_begin(NULL, true, workers);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < sizeof(rnd); i++) {
		rnd[i] = (uint8_t)isc_random_uniform(100);
	}

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_test_end();

	return (0);
}

static int
rwlock_setup(void **state) {
	UNUSED(state);

	isc__rwlock_setworkers(2 + ncpus * 2);

	isc_rwlock_init_ex(&rwlock, ISC_RWLOCK_IMPL_RW_WP);

	if (sem_init(&sem1, 0, 0) == -1) {
		return (errno);
	}
	if (sem_init(&sem2, 0, 0) == -1) {
		return (errno);
	}
	if (pthread_rwlock_init(&prwlock, NULL) == -1) {
		return (errno);
	}

	return (0);
}

static int
rwlock_teardown(void **state) {
	UNUSED(state);

	if (pthread_rwlock_destroy(&prwlock) == -1) {
		return (errno);
	}
	if (sem_destroy(&sem2) == -1) {
		return (errno);
	}
	if (sem_destroy(&sem1) == -1) {
		return (errno);
	}

	isc_rwlock_destroy(&rwlock);

	return (0);
}

/*
 * Simple single-threaded read lock/unlock test
 */
static void
isc_rwlock_rdlock_test(void **state) {
	UNUSED(state);

	isc_rwlock_lock(&rwlock, isc_rwlocktype_read);
	isc_pause(DELAY_LOOP);
	isc_rwlock_unlock(&rwlock, isc_rwlocktype_read);
}

/*
 * Simple single-threaded write lock/unlock test
 */
static void
isc_rwlock_wrlock_test(void **state) {
	UNUSED(state);

	isc_rwlock_lock(&rwlock, isc_rwlocktype_write);
	isc_pause(DELAY_LOOP);
	isc_rwlock_unlock(&rwlock, isc_rwlocktype_write);
}

/*
 * Simple single-threaded lock/downgrade/unlock test
 */
static void
isc_rwlock_downgrade_test(void **state) {
	UNUSED(state);

	isc_rwlock_lock(&rwlock, isc_rwlocktype_write);
	isc_rwlock_downgrade(&rwlock);
	isc_rwlock_unlock(&rwlock, isc_rwlocktype_read);
}

/*
 * Simple single-threaded lock/tryupgrade/unlock test
 */
static void
isc_rwlock_tryupgrade_test(void **state) {
	UNUSED(state);

#if __SANITIZE_THREAD__
	skip();
#else  /* __SANITIZE_THREAD */
	isc_result_t result;
	isc_rwlock_lock(&rwlock, isc_rwlocktype_read);
	result = isc_rwlock_tryupgrade(&rwlock);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_rwlock_unlock(&rwlock, isc_rwlocktype_write);
#endif /* __SANITIZE_THREAD__ */
}

static isc_threadresult_t
trylock_thread1(isc_threadarg_t arg) {
	UNUSED(arg);

	isc_rwlock_lock(&rwlock, isc_rwlocktype_write);

	sem_post(&sem1);
	sem_wait(&sem2);

	isc_rwlock_unlock(&rwlock, isc_rwlocktype_write);

	isc_rwlock_lock(&rwlock, isc_rwlocktype_read);

	sem_post(&sem1);
	sem_wait(&sem2);

	isc_rwlock_unlock(&rwlock, isc_rwlocktype_read);

	return ((isc_threadresult_t)0);
}

static isc_threadresult_t
trylock_thread2(isc_threadarg_t arg) {
	isc_result_t result;

	UNUSED(arg);

	sem_wait(&sem1);

	result = isc_rwlock_trylock(&rwlock, isc_rwlocktype_read);
	assert_int_equal(result, ISC_R_LOCKBUSY);

	sem_post(&sem2);

	sem_wait(&sem1);

	result = isc_rwlock_trylock(&rwlock, isc_rwlocktype_read);
	assert_int_equal(result, ISC_R_SUCCESS);

	sem_post(&sem2);

	isc_rwlock_unlock(&rwlock, isc_rwlocktype_read);

	return ((isc_threadresult_t)0);
}

static void
isc_rwlock_trylock_test(void **state) {
	UNUSED(state);
	isc_thread_t thread1;
	isc_thread_t thread2;

	isc_thread_create(trylock_thread1, NULL, &thread1);
	isc_thread_create(trylock_thread2, NULL, &thread2);

	isc_thread_join(thread2, NULL);
	isc_thread_join(thread1, NULL);
}

static isc_threadresult_t
pthread_rwlock_thread(isc_threadarg_t arg) {
	/* size_t cont = *(size_t *)arg; */

	UNUSED(arg);

	for (size_t i = 0; i < LOOPS; i++) {
		if (rnd[i] < boundary) {
			pthread_rwlock_wrlock(&prwlock);
			size_t v = shared_counter;
			isc_pause(DELAY_LOOP);
			shared_counter = v + 1;
			pthread_rwlock_unlock(&prwlock);
		} else {
			pthread_rwlock_rdlock(&prwlock);
			isc_pause(DELAY_LOOP);
			pthread_rwlock_unlock(&prwlock);
		}
		/* isc_pause(cont); */
	}

	return ((isc_threadresult_t)0);
}

static isc_threadresult_t
isc_rwlock_thread(isc_threadarg_t arg) {
	/* size_t cont = *(size_t *)arg; */

	UNUSED(arg);

	for (size_t i = 0; i < LOOPS; i++) {
		if (rnd[i] < boundary) {
			isc_rwlock_lock(&rwlock, isc_rwlocktype_write);
			size_t v = shared_counter;
			isc_pause(DELAY_LOOP);
			shared_counter = v + 1;
			isc_rwlock_unlock(&rwlock, isc_rwlocktype_write);
		} else {
			isc_rwlock_lock(&rwlock, isc_rwlocktype_read);
			isc_pause(DELAY_LOOP);
			isc_rwlock_unlock(&rwlock, isc_rwlocktype_read);
		}
		/* isc_pause(cont); */
	}

	return ((isc_threadresult_t)0);
}

static void
isc__rwlock_benchmark(isc_thread_t *threads, unsigned int nthreads,
		      uint8_t pct) {
	isc_time_t ts1, ts2;
	double t;
	isc_result_t result;
	int dc;
	size_t cont;

	expected_counter = ITERS * nthreads * LOOPS *
			   ((CNT_MAX - CNT_MIN) / DC + 1);

	boundary = pct;

	/* PTHREAD RWLOCK */

	result = isc_time_now_hires(&ts1);
	assert_int_equal(result, ISC_R_SUCCESS);

	shared_counter = 0;
	dc = DC;
	for (size_t l = 0; l < ITERS; l++) {
		for (cont = (dc > 0) ? CNT_MIN : CNT_MAX;
		     cont <= CNT_MAX && cont >= CNT_MIN; cont += dc)
		{
			for (size_t i = 0; i < nthreads; i++) {
				isc_thread_create(pthread_rwlock_thread, &cont,
						  &threads[i]);
			}
			for (size_t i = 0; i < nthreads; i++) {
				isc_thread_join(threads[i], NULL);
			}
		}
		dc = -dc;
	}

	result = isc_time_now_hires(&ts2);
	assert_int_equal(result, ISC_R_SUCCESS);

	t = isc_time_microdiff(&ts2, &ts1);

	printf("[ TIME     ] isc_rwlock_benchmark: %zu pthread_rwlock loops in "
	       "%u threads, %2.3f%% writes, %2.3f seconds, %2.3f "
	       "calls/second\n",
	       expected_counter, nthreads,
	       (double)shared_counter * 100 / expected_counter, t / 1000000.0,
	       expected_counter / (t / 1000000.0));

	/* ISC RWLOCK */

	result = isc_time_now_hires(&ts1);
	assert_int_equal(result, ISC_R_SUCCESS);

	dc = DC;
	shared_counter = 0;
	for (size_t l = 0; l < ITERS; l++) {
		for (cont = (dc > 0) ? CNT_MIN : CNT_MAX;
		     cont <= CNT_MAX && cont >= CNT_MIN; cont += dc)
		{
			for (size_t i = 0; i < nthreads; i++) {
				isc_thread_create(isc_rwlock_thread, &cont,
						  &threads[i]);
			}
			for (size_t i = 0; i < nthreads; i++) {
				isc_thread_join(threads[i], NULL);
			}
		}
		dc = -dc;
	}

	result = isc_time_now_hires(&ts2);
	assert_int_equal(result, ISC_R_SUCCESS);

	t = isc_time_microdiff(&ts2, &ts1);

	printf("[ TIME     ] isc_rwlock_benchmark: %zu isc_rwlock loops in "
	       "%u threads, %2.3f%% writes, %2.3f seconds, %2.3f "
	       "calls/second\n",
	       expected_counter, nthreads,
	       (double)shared_counter * 100 / expected_counter, t / 1000000.0,
	       expected_counter / (t / 1000000.0));
}

static void
isc_rwlock_benchmark(void **state) {
	UNUSED(state);

#if defined(__SANITIZE_THREAD__)
	UNUSED(isc__rwlock_benchmark);

	skip();
#else
	SKIP_IN_CI;

	isc_thread_t *threads = isc_mem_get(test_mctx,
					    sizeof(*threads) * workers);

	memset(threads, 0, sizeof(*threads) * workers);

	for (unsigned int nthreads = workers; nthreads > 0; nthreads /= 2) {
		isc__rwlock_benchmark(threads, nthreads, 0);
		isc__rwlock_benchmark(threads, nthreads, 1);
		isc__rwlock_benchmark(threads, nthreads, 10);
		isc__rwlock_benchmark(threads, nthreads, 50);
		isc__rwlock_benchmark(threads, nthreads, 90);
		isc__rwlock_benchmark(threads, nthreads, 99);
		isc__rwlock_benchmark(threads, nthreads, 100);
	}

	isc_mem_put(test_mctx, threads, sizeof(*threads) * workers);
#endif /* __SANITIZE_THREAD__ */
}

/*
 * Main
 */

int
main(void) {
	if (getenv("CI") != NULL && getenv("CI_ENABLE_ALL_TESTS") == NULL) {
		skip_long_tests = true;
	}

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(isc_rwlock_rdlock_test,
						rwlock_setup, rwlock_teardown),
		cmocka_unit_test_setup_teardown(isc_rwlock_wrlock_test,
						rwlock_setup, rwlock_teardown),
		cmocka_unit_test_setup_teardown(isc_rwlock_downgrade_test,
						rwlock_setup, rwlock_teardown),

		cmocka_unit_test_setup_teardown(isc_rwlock_tryupgrade_test,
						rwlock_setup, rwlock_teardown),
		cmocka_unit_test_setup_teardown(isc_rwlock_trylock_test,
						rwlock_setup, rwlock_teardown),
		cmocka_unit_test_setup_teardown(isc_rwlock_benchmark,
						rwlock_setup, rwlock_teardown),
	};

	return (cmocka_run_group_tests(tests, _setup, _teardown));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
