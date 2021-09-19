/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <inttypes.h>
#include <stdlib.h>

#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "trampoline_p.h"

#define ISC__TRAMPOLINE_UNUSED 0

struct isc__trampoline {
	int tid; /* const */
	uintptr_t self;
	isc_threadfunc_t start;
	isc_threadarg_t arg;
};

static isc_once_t isc__trampoline_initialize_once = ISC_ONCE_INIT;
static isc_once_t isc__trampoline_shutdown_once = ISC_ONCE_INIT;
static isc_mutex_t isc__trampoline_lock;
static isc__trampoline_t **trampolines;
thread_local size_t isc_tid_v = SIZE_MAX;
static size_t isc__trampoline_min = 1;
static size_t isc__trampoline_max = 65;

/*
 * We can't use isc_mem API here, because it's called too early and the
 * isc_mem_debugging flags can be changed later causing mismatch between flags
 * used for isc_mem_get() and isc_mem_put().
 *
 * Since this is a single allocation at library load and deallocation at library
 * unload, using the standard allocator without the tracking is fine for this
 * single purpose.
 */
static isc__trampoline_t *
isc__trampoline_new(int tid, isc_threadfunc_t start, isc_threadarg_t arg) {
	isc__trampoline_t *trampoline = calloc(1, sizeof(*trampoline));
	RUNTIME_CHECK(trampoline != NULL);

	*trampoline = (isc__trampoline_t){
		.tid = tid,
		.start = start,
		.arg = arg,
		.self = ISC__TRAMPOLINE_UNUSED,
	};

	return (trampoline);
}

static void
trampoline_initialize(void) {
	isc_mutex_init(&isc__trampoline_lock);

	trampolines = calloc(isc__trampoline_max, sizeof(trampolines[0]));
	RUNTIME_CHECK(trampolines != NULL);

	/* Get the trampoline slot 0 for the main thread */
	trampolines[0] = isc__trampoline_new(0, NULL, NULL);
	trampolines[0]->self = isc_thread_self();
	isc_tid_v = trampolines[0]->tid;

	/* Initialize the other trampolines */
	for (size_t i = 1; i < isc__trampoline_max; i++) {
		trampolines[i] = NULL;
	}
	isc__trampoline_min = 1;
}

void
isc__trampoline_initialize(void) {
	isc_result_t result = isc_once_do(&isc__trampoline_initialize_once,
					  trampoline_initialize);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

static void
trampoline_shutdown(void) {
	/*
	 * When the program using the library exits abruptly and the library
	 * gets unloaded, there might be some existing trampolines from unjoined
	 * threads.  We intentionally ignore those and don't check whether all
	 * trampolines have been cleared before exiting.
	 */
	free(trampolines[0]);
	free(trampolines);
	trampolines = NULL;
	isc_mutex_destroy(&isc__trampoline_lock);
}

void
isc__trampoline_shutdown(void) {
	isc_result_t result = isc_once_do(&isc__trampoline_shutdown_once,
					  trampoline_shutdown);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

isc__trampoline_t *
isc__trampoline_get(isc_threadfunc_t start, isc_threadarg_t arg) {
	isc__trampoline_t **tmp = NULL;
	isc__trampoline_t *trampoline = NULL;
	LOCK(&isc__trampoline_lock);
again:
	for (size_t i = isc__trampoline_min; i < isc__trampoline_max; i++) {
		if (trampolines[i] == NULL) {
			trampoline = isc__trampoline_new(i, start, arg);
			trampolines[i] = trampoline;
			isc__trampoline_min = i + 1;
			goto done;
		}
	}
	tmp = calloc(2 * isc__trampoline_max, sizeof(trampolines[0]));
	RUNTIME_CHECK(tmp != NULL);
	for (size_t i = 0; i < isc__trampoline_max; i++) {
		tmp[i] = trampolines[i];
	}
	for (size_t i = isc__trampoline_max; i < 2 * isc__trampoline_max; i++) {
		tmp[i] = NULL;
	}
	free(trampolines);
	trampolines = tmp;
	isc__trampoline_max = isc__trampoline_max * 2;
	goto again;
done:
	INSIST(trampoline != NULL);
	UNLOCK(&isc__trampoline_lock);

	return (trampoline);
}

void
isc__trampoline_detach(isc__trampoline_t *trampoline) {
	LOCK(&isc__trampoline_lock);
	REQUIRE(trampoline->tid > 0 &&
		(size_t)trampoline->tid < isc__trampoline_max);
	REQUIRE(trampoline->self == isc_thread_self());
	REQUIRE(trampolines[trampoline->tid] == trampoline);

	trampolines[trampoline->tid] = NULL;

	if (isc__trampoline_min > (size_t)trampoline->tid) {
		isc__trampoline_min = trampoline->tid;
	}

	free(trampoline);

	UNLOCK(&isc__trampoline_lock);
	return;
}

void
isc__trampoline_attach(isc__trampoline_t *trampoline) {
	REQUIRE(trampoline->tid > 0 &&
		(size_t)trampoline->tid < isc__trampoline_max);
	REQUIRE(trampoline->self == ISC__TRAMPOLINE_UNUSED);

	/* Initialize the trampoline */
	isc_tid_v = trampoline->tid;
	trampoline->self = isc_thread_self();
}

isc_threadresult_t
isc__trampoline_run(isc_threadarg_t arg) {
	isc__trampoline_t *trampoline = (isc__trampoline_t *)arg;
	isc_threadresult_t result;

	isc__trampoline_attach(trampoline);

	/* Run the main function */
	result = (trampoline->start)(trampoline->arg);

	isc__trampoline_detach(trampoline);

	return (result);
}
