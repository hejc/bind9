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

#pragma once

#include <inttypes.h>

/*! \file isc/rwlock.h */

#include <isc/align.h>
#include <isc/atomic.h>
#include <isc/condition.h>
#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

typedef enum {
	isc_rwlocktype_none = 0,
	isc_rwlocktype_read,
	isc_rwlocktype_write
} isc_rwlocktype_t;

typedef enum {
	ISC_RWLOCK_IMPL_NATIVE = 0,
	ISC_RWLOCK_IMPL_RW_WP,
} isc_rwlock_impl_t;

#define ISC_RWLOCK_UNLOCKED false
#define ISC_RWLOCK_LOCKED   true

#define ISC_CACHE_LINE 64 /* FIXME: Pull from configure */

#define ISC_RWLOCK_COUNTERS_RATIO \
	(ISC_CACHE_LINE / sizeof(atomic_uint_fast32_t))

typedef struct isc__rwlock {
	uint16_t hashbits;
	uint16_t ncounters;
	alignas(ISC_CACHE_LINE) atomic_uint_fast32_t *ingress_counters;
	alignas(ISC_CACHE_LINE) atomic_uint_fast32_t *egress_counters;
	alignas(ISC_CACHE_LINE) atomic_int_fast32_t writers_barrier;
	alignas(ISC_CACHE_LINE) atomic_bool writers_lock;
} isc__rwlock_t;

struct isc_rwlock {
	unsigned int	  magic;
	isc_rwlock_impl_t impl;
	alignas(ISC_CACHE_LINE) union {
		pthread_rwlock_t native;
		isc__rwlock_t	 custom;
	};
};

void
isc_rwlock_init_ex(isc_rwlock_t *rwl, isc_rwlock_impl_t impl);

void
isc_rwlock_init(isc_rwlock_t *rwl);

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_tryupgrade(isc_rwlock_t *rwl);

void
isc_rwlock_downgrade(isc_rwlock_t *rwl);

void
isc_rwlock_destroy(isc_rwlock_t *rwl);

ISC_LANG_ENDDECLS
