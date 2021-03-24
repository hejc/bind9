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

#if defined(_MSC_VER)
#include <intrin.h>
#define isc__pause() YieldProcessor()
#elif defined(__x86_64__)
#include <immintrin.h>
#define isc__pause() _mm_pause()
#elif defined(__i386__)
#define isc__pause() __asm__ __volatile__("rep; nop")
#elif defined(__ia64__)
#define isc__pause() __asm__ __volatile__("hint @pause")
#elif defined(__arm__) && HAVE_ARM_YIELD
#define isc__pause() __asm__ __volatile__("yield")
#elif defined(sun) && (defined(__sparc) || defined(__sparc__))
#include <synch.h>
#define isc__pause() smt_pause()
#elif (defined(__sparc) || defined(__sparc__)) && HAVE_SPARC_PAUSE
#define isc__pause() __asm__ __volatile__("pause")
#elif defined(__ppc__) || defined(_ARCH_PPC) || defined(_ARCH_PWR) || \
	defined(_ARCH_PWR2) || defined(_POWER)
#define isc__pause() __asm__ volatile("or 27,27,27")
#else /* if defined(_MSC_VER) */
#define isc__pause() sched_yield()
#endif /* if defined(_MSC_VER) */

#define isc_pause(iters)                                       \
	for (size_t __pause = 0; __pause < iters; __pause++) { \
		isc__pause();                                  \
	}
