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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/magic.h>
#include <isc/once.h>
#include <isc/pause.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#include "rwlock_p.h"

/*
 * Modified C-RW-WP Implementation from NUMA-Aware Reader-Writer Locks paper:
 * http://dl.acm.org/citation.cfm?id=2442532
 *
 * This work is based on C++ code available from
 * https://github.com/pramalhe/ConcurrencyFreaks/
 *
 * Copyright (c) 2014-2016, Pedro Ramalhete, Andreia Correia
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Concurrency Freaks nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER>
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#define RWLOCK_MAGIC	  ISC_MAGIC('R', 'W', 'W', 'P')
#define VALID_RWLOCK(rwl) ISC_MAGIC_VALID(rwl, RWLOCK_MAGIC)

#include <stdlib.h>

#include <isc/mem.h>
#include <isc/os.h>
#include <isc/thread.h>

#define HASHSIZE(bits)	(UINT64_C(1) << (bits))
#define HASH_MIN_BITS	1
#define HASH_MAX_BITS	32
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static atomic_uint_fast16_t isc__rwlock_workers = 0;

static inline size_t
tid2idx(isc__rwlock_t *rwl) {
	REQUIRE(isc_tid_v * ISC_RWLOCK_COUNTERS_RATIO < rwl->ncounters);

	return (isc_tid_v * ISC_RWLOCK_COUNTERS_RATIO);
}

/*
 * See https://csce.ucmss.com/cr/books/2017/LFS/CSREA2017/FCS3701.pdf for
 * guidance on patience level
 */
#ifndef RWLOCK_MAX_READER_PATIENCE
#define RWLOCK_MAX_READER_PATIENCE 500
#endif /* ifndef RWLOCK_MAX_READER_PATIENCE */

static inline bool
read_indicator_isempty(isc__rwlock_t *rwl);

static inline void
read_indicator_wait_until_empty(isc__rwlock_t *rwl);

static inline void
read_indicator_arrive(isc__rwlock_t *rwl, size_t idx) {
	(void)atomic_fetch_add_release(&rwl->ingress_counters[idx], 1);
}

static inline void
read_indicator_depart(isc__rwlock_t *rwl, size_t idx) {
	(void)atomic_fetch_add_release(&rwl->egress_counters[idx], 1);
}

static inline bool
read_indicator_iszero(isc__rwlock_t *rwl, size_t idx) {
	return (atomic_load_relaxed(&rwl->egress_counters[idx]) ==
		atomic_load_relaxed(&rwl->ingress_counters[idx]));
}

static inline void
writers_barrier_raise(isc__rwlock_t *rwl) {
	(void)atomic_fetch_add_release(&rwl->writers_barrier, 1);
}

static inline void
writers_barrier_lower(isc__rwlock_t *rwl) {
	(void)atomic_fetch_sub_release(&rwl->writers_barrier, 1);
}

static inline bool
writers_barrier_israised(isc__rwlock_t *rwl) {
	return (atomic_load_acquire(&rwl->writers_barrier) > 0);
}

static inline bool
writers_lock_islocked(isc__rwlock_t *rwl) {
	return (atomic_load_acquire(&rwl->writers_lock) == ISC_RWLOCK_LOCKED);
}

static inline bool
writers_lock_acquire(isc__rwlock_t *rwl) {
	return (atomic_compare_exchange_weak_acq_rel(
		&rwl->writers_lock, &(bool){ ISC_RWLOCK_UNLOCKED },
		ISC_RWLOCK_LOCKED));
}

static inline void
writers_lock_release(isc__rwlock_t *rwl) {
	REQUIRE(atomic_compare_exchange_strong_acq_rel(
		&rwl->writers_lock, &(bool){ ISC_RWLOCK_LOCKED },
		ISC_RWLOCK_UNLOCKED));
}

#define ran_out_of_patience(cnt) (cnt >= RWLOCK_MAX_READER_PATIENCE)

static inline void
isc__rwlock_shared_lock(isc__rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);
	uint32_t cnt = 0;
	bool barrier_raised = false;

	while (true) {
		read_indicator_arrive(rwl, idx);
		if (!writers_lock_islocked(rwl)) {
			/* Acquired lock in read-only mode */
			break;
		}

		/* Writer has acquired the lock, must reset to 0 and wait */
		read_indicator_depart(rwl, idx);

		while (writers_lock_islocked(rwl)) {
			isc_pause(1);
			if (ISC_UNLIKELY(ran_out_of_patience(cnt++) &&
					 !barrier_raised)) {
				writers_barrier_raise(rwl);
				barrier_raised = true;
			}
		}
	}
	if (barrier_raised) {
		writers_barrier_lower(rwl);
	}
}

static inline isc_result_t
isc__rwlock_shared_trylock(isc__rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);

	read_indicator_arrive(rwl, idx);
	if (writers_lock_islocked(rwl)) {
		/* Writer has acquired the lock, must reset to 0 */
		read_indicator_depart(rwl, idx);

		return (ISC_R_LOCKBUSY);
	}

	/* Acquired lock in read-only mode */
	return (ISC_R_SUCCESS);
}

static inline void
isc__rwlock_shared_unlock(isc__rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);

	read_indicator_depart(rwl, idx);
}

static inline isc_result_t
isc__rwlock_shared_tryupgrade(isc__rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);

	/* Write Barriers has been raised */
	if (writers_barrier_israised(rwl)) {
		return (ISC_R_LOCKBUSY);
	}

	/* Try to acquire the write-lock */
	if (!writers_lock_acquire(rwl)) {
		return (ISC_R_LOCKBUSY);
	}

	/* Unlock the read-lock */
	read_indicator_depart(rwl, idx);

	if (!read_indicator_isempty(rwl)) {
		/* Re-acquire the read-lock back */
		read_indicator_arrive(rwl, idx);

		/* Unlock the write-lock */
		writers_lock_release(rwl);
		return (ISC_R_LOCKBUSY);
	}
	return (ISC_R_SUCCESS);
}

static inline bool
read_indicator_isempty(isc__rwlock_t *rwl) {
	/* Write-lock was acquired, now wait for running Readers to finish */

	for (size_t idx = 0; idx < rwl->ncounters;
	     idx += ISC_RWLOCK_COUNTERS_RATIO) {
		if (!read_indicator_iszero(rwl, idx)) {
			return (false);
		}
	}

	return (true);
}

static inline void
read_indicator_wait_until_empty(isc__rwlock_t *rwl) {
	/* Write-lock was acquired, now wait for running Readers to finish */
	for (size_t idx = 0; idx < rwl->ncounters;
	     idx += ISC_RWLOCK_COUNTERS_RATIO) {
		while (true) {
			if (read_indicator_iszero(rwl, idx)) {
				break;
			}
			isc_pause(1);
		}
	}
}

static inline void
isc__rwlock_exclusive_lock(isc__rwlock_t *rwl) {
	/* Write Barriers has been raised, wait */
	while (writers_barrier_israised(rwl)) {
		isc_pause(1);
	}

	/* Try to acquire the write-lock */
	while (!writers_lock_acquire(rwl)) {
		isc_pause(1);
	}

	read_indicator_wait_until_empty(rwl);
}

static void
isc__rwlock_exclusive_unlock(isc__rwlock_t *rwl) {
	writers_lock_release(rwl);
}

static isc_result_t
isc__rwlock_exclusive_trylock(isc__rwlock_t *rwl) {
	/* Write Barriers has been raised */
	if (writers_barrier_israised(rwl)) {
		return (ISC_R_LOCKBUSY);
	}

	/* Try to acquire the write-lock */
	if (!writers_lock_acquire(rwl)) {
		return (ISC_R_LOCKBUSY);
	}

	if (!read_indicator_isempty(rwl)) {
		/* Unlock the write-lock */
		writers_lock_release(rwl);

		return (ISC_R_LOCKBUSY);
	}

	return (ISC_R_SUCCESS);
}

static inline void
isc__rwlock_exclusive_downgrade(isc__rwlock_t *rwl) {
	const size_t idx = tid2idx(rwl);

	read_indicator_arrive(rwl, idx);

	writers_lock_release(rwl);
}

void
isc__rwlock_setworkers(uint16_t workers) {
	atomic_store(&isc__rwlock_workers, workers);
}

static inline void
isc__rwlock_init(isc__rwlock_t *rwl) {
	REQUIRE(rwl != NULL);
	REQUIRE(isc__rwlock_workers > 0);

	atomic_init(&rwl->writers_lock, ISC_RWLOCK_UNLOCKED);
	atomic_init(&rwl->writers_barrier, 0);

	rwl->hashbits = HASH_MIN_BITS;

	while (isc__rwlock_workers > HASHSIZE(rwl->hashbits)) {
		rwl->hashbits += 1;
	}

	RUNTIME_CHECK(rwl->hashbits > 0 && rwl->hashbits <= HASH_MAX_BITS);
	rwl->ncounters = HASHSIZE(rwl->hashbits) * ISC_RWLOCK_COUNTERS_RATIO;

	/*
	 * NOTE: We don't use isc_mem API for allocating the memory
	 * here because there's underlying assumption that rwlocks do
	 * not require explicit call to dtor.
	 */
	rwl->ingress_counters = aligned_alloc(
		ISC_CACHE_LINE,
		rwl->ncounters * sizeof(rwl->ingress_counters[0]));
	rwl->egress_counters =
		aligned_alloc(ISC_CACHE_LINE,
			      rwl->ncounters * sizeof(rwl->egress_counters[0]));
	memset(rwl->ingress_counters, 0,
	       rwl->ncounters * sizeof(rwl->ingress_counters[0]));
	memset(rwl->egress_counters, 0,
	       rwl->ncounters * sizeof(rwl->egress_counters[0]));
}

void
isc_rwlock_init_ex(isc_rwlock_t *rwl, isc_rwlock_impl_t impl) {
	REQUIRE(rwl != NULL);

#if __SANITIZE_THREAD__
	/* Use native rwlock with thread sanitizer */
	impl = ISC_RWLOCK_IMPL_NATIVE;
	workers = 0;
#endif

	switch (impl) {
	case ISC_RWLOCK_IMPL_NATIVE:
		REQUIRE(pthread_rwlock_init(&rwl->native, NULL) == 0);

		break;
	case ISC_RWLOCK_IMPL_RW_WP:

		isc__rwlock_init(&rwl->custom);

		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}

	rwl->impl = impl;
	rwl->magic = RWLOCK_MAGIC;
}

void
isc_rwlock_init(isc_rwlock_t *rwl) {
	REQUIRE(rwl != NULL);

	isc_rwlock_init_ex(rwl, ISC_RWLOCK_IMPL_NATIVE);
}

static inline void
isc__rwlock_destroy(isc__rwlock_t *rwl) {
	/* Check whether write lock has been unlocked */
	REQUIRE(atomic_load(&rwl->writers_lock) == ISC_RWLOCK_UNLOCKED);

	if (rwl->ncounters == 0) {
		REQUIRE(read_indicator_iszero(rwl, 0));
	} else {
		/* Check whether all read locks has been unlocked */
		for (size_t i = 0; i < rwl->ncounters;
		     i += ISC_RWLOCK_COUNTERS_RATIO) {
			REQUIRE(read_indicator_iszero(rwl, i));
		}

		free(rwl->ingress_counters);
		free(rwl->egress_counters);
	}
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));
	rwl->magic = 0;

	switch (rwl->impl) {
	case ISC_RWLOCK_IMPL_NATIVE:
		pthread_rwlock_destroy(&rwl->native);
		break;
	case ISC_RWLOCK_IMPL_RW_WP:
		isc__rwlock_destroy(&rwl->custom);
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (rwl->impl) {
	case ISC_RWLOCK_IMPL_NATIVE:
		switch (type) {
		case isc_rwlocktype_read:
			pthread_rwlock_rdlock(&rwl->native);
			break;
		case isc_rwlocktype_write:
			pthread_rwlock_wrlock(&rwl->native);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		break;
	case ISC_RWLOCK_IMPL_RW_WP:
		switch (type) {
		case isc_rwlocktype_read:
			isc__rwlock_shared_lock(&rwl->custom);
			break;
		case isc_rwlocktype_write:
			isc__rwlock_exclusive_lock(&rwl->custom);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	int r;

	REQUIRE(VALID_RWLOCK(rwl));

	switch (rwl->impl) {
	case ISC_RWLOCK_IMPL_NATIVE:
		switch (type) {
		case isc_rwlocktype_read:
			r = pthread_rwlock_tryrdlock(&rwl->native);
			break;
		case isc_rwlocktype_write:
			r = pthread_rwlock_trywrlock(&rwl->native);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		switch (r) {
		case 0:
			return (ISC_R_SUCCESS);
		case EBUSY:
		case EAGAIN:
			return (ISC_R_LOCKBUSY);
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		break;
	case ISC_RWLOCK_IMPL_RW_WP:
		switch (type) {
		case isc_rwlocktype_read:
			return (isc__rwlock_shared_trylock(&rwl->custom));
			break;
		case isc_rwlocktype_write:
			return (isc__rwlock_exclusive_trylock(&rwl->custom));
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (rwl->impl) {
	case ISC_RWLOCK_IMPL_NATIVE:
		switch (type) {
		case isc_rwlocktype_read:
		case isc_rwlocktype_write:
			pthread_rwlock_unlock(&rwl->native);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		break;
	case ISC_RWLOCK_IMPL_RW_WP:
		switch (type) {
		case isc_rwlocktype_read:
			isc__rwlock_shared_unlock(&rwl->custom);
			break;
		case isc_rwlocktype_write:
			isc__rwlock_exclusive_unlock(&rwl->custom);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (rwl->impl) {
	case ISC_RWLOCK_IMPL_NATIVE:
		return (ISC_R_LOCKBUSY);
	case ISC_RWLOCK_IMPL_RW_WP:
		return (isc__rwlock_shared_tryupgrade(&rwl->custom));
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {
	REQUIRE(VALID_RWLOCK(rwl));

	switch (rwl->impl) {
	case ISC_RWLOCK_IMPL_NATIVE:
		return;
	case ISC_RWLOCK_IMPL_RW_WP:
		isc__rwlock_exclusive_downgrade(&rwl->custom);
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}
