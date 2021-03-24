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
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/pause.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/stdio.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/util.h>

#include "isctest.h"

#define LOOPS	   1000
#define DELAY_LOOP 100

static unsigned int workers = 0;

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

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	isc_test_end();

	return (0);
}

static void
isc_mutex_test(void **state) {
	isc_mutex_t lock;

	UNUSED(state);

	isc_mutex_init(&lock);

	for (size_t i = 0; i < LOOPS; i++) {
		isc_mutex_lock(&lock);
		isc_pause(DELAY_LOOP);
		isc_mutex_unlock(&lock);
	}

	isc_mutex_destroy(&lock);
}

#define ITERS 20

#define DC	200
#define CNT_MIN 800
#define CNT_MAX 1600

static size_t shared_counter = 0;
static size_t expected_counter = SIZE_MAX;
static isc_mutex_t lock;
static pthread_mutex_t mutex;

static isc_threadresult_t
pthread_mutex_thread(isc_threadarg_t arg) {
	size_t cont = *(size_t *)arg;

	for (size_t i = 0; i < LOOPS; i++) {
		pthread_mutex_lock(&mutex);
		size_t v = shared_counter;
		isc_pause(DELAY_LOOP);
		shared_counter = v + 1;
		pthread_mutex_unlock(&mutex);
		isc_pause(cont);
	}

	return ((isc_threadresult_t)0);
}

static isc_threadresult_t
isc_mutex_thread(isc_threadarg_t arg) {
	size_t cont = *(size_t *)arg;

	for (size_t i = 0; i < LOOPS; i++) {
		isc_mutex_lock(&lock);
		size_t v = shared_counter;
		isc_pause(DELAY_LOOP);
		shared_counter = v + 1;
		isc_mutex_unlock(&lock);
		isc_pause(cont);
	}

	return ((isc_threadresult_t)0);
}

static void
isc_mutex_benchmark(void **state) {
	UNUSED(state);

#if defined(__SANITIZE_THREAD__)
	UNUSED(expected_counter);
	UNUSED(pthread_mutex_thread);
	UNUSED(isc_mutex_thread);

	skip();
#else
	SKIP_IN_CI;

	isc_thread_t *threads = isc_mem_get(test_mctx,
					    sizeof(*threads) * workers);
	isc_time_t ts1, ts2;
	double t;
	isc_result_t result;
	int dc;
	size_t cont;
	int r;

	memset(threads, 0, sizeof(*threads) * workers);

	expected_counter = ITERS * workers * LOOPS *
			   ((CNT_MAX - CNT_MIN) / DC + 1);

	/* PTHREAD MUTEX */

	r = pthread_mutex_init(&mutex, NULL);
	assert_int_not_equal(r, -1);

	result = isc_time_now_hires(&ts1);
	assert_int_equal(result, ISC_R_SUCCESS);

	shared_counter = 0;
	dc = DC;
	for (size_t l = 0; l < ITERS; l++) {
		for (cont = (dc > 0) ? CNT_MIN : CNT_MAX;
		     cont <= CNT_MAX && cont >= CNT_MIN; cont += dc)
		{
			for (size_t i = 0; i < workers; i++) {
				isc_thread_create(pthread_mutex_thread, &cont,
						  &threads[i]);
			}
			for (size_t i = 0; i < workers; i++) {
				isc_thread_join(threads[i], NULL);
			}
		}
		dc = -dc;
	}
	assert_int_equal(shared_counter, expected_counter);

	result = isc_time_now_hires(&ts2);
	assert_int_equal(result, ISC_R_SUCCESS);

	t = isc_time_microdiff(&ts2, &ts1);

	printf("[ TIME     ] isc_mutex_benchmark: %zu pthread_mutex loops in "
	       "%u threads, %2.3f seconds, %2.3f calls/second\n",
	       shared_counter, workers, t / 1000000.0,
	       shared_counter / (t / 1000000.0));

	r = pthread_mutex_destroy(&mutex);
	assert_int_not_equal(r, -1);

	/* ISC MUTEX */

	isc_mutex_init(&lock);

	result = isc_time_now_hires(&ts1);
	assert_int_equal(result, ISC_R_SUCCESS);

	dc = DC;
	shared_counter = 0;
	for (size_t l = 0; l < ITERS; l++) {
		for (cont = (dc > 0) ? CNT_MIN : CNT_MAX;
		     cont <= CNT_MAX && cont >= CNT_MIN; cont += dc)
		{
			for (size_t i = 0; i < workers; i++) {
				isc_thread_create(isc_mutex_thread, &cont,
						  &threads[i]);
			}
			for (size_t i = 0; i < workers; i++) {
				isc_thread_join(threads[i], NULL);
			}
		}
		dc = -dc;
	}
	assert_int_equal(shared_counter, expected_counter);

	result = isc_time_now_hires(&ts2);
	assert_int_equal(result, ISC_R_SUCCESS);

	t = isc_time_microdiff(&ts2, &ts1);

	printf("[ TIME     ] isc_mutex_benchmark: %zu isc_mutex loops in %u "
	       "threads, %2.3f seconds, %2.3f calls/second\n",
	       shared_counter, workers, t / 1000000.0,
	       shared_counter / (t / 1000000.0));

	isc_mutex_destroy(&lock);

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
		cmocka_unit_test_setup_teardown(isc_mutex_test, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(isc_mutex_benchmark, _setup,
						_teardown),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
