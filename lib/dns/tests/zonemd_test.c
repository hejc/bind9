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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING

#include <isc/cmocka.h>
#include <isc/commandline.h>
#include <isc/print.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/zonemd.h>

#include "dnstest.h"

static bool debug = false;

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = dns_test_begin(NULL, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	dns_test_end();

	return (0);
}

/*
 * Individual unit tests
 */

/* zonemd_buildrdata */
static void
zonemd_buildrdata(void **state) {
	dns_db_t *db = NULL;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_buffer_t target;
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	unsigned char buf[DNS_ZONEMD_BUFFERSIZE];
	char text[1024] = { 0 };
	dns_rdata_zonemd_t zonemd;

	UNUSED(state);

	isc_mem_create(&mctx);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "example",
				 "testdata/zonemd/rfc8976.A.1.db");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_zonemd_buildrdata(
		&rdata, db, NULL, DNS_ZONEMD_SCHEME_SIMPLE,
		DNS_ZONEMD_DIGEST_SHA384, mctx, buf, sizeof(buf));
	assert_int_equal(result, ISC_R_SUCCESS);

	if (debug) {
		isc_buffer_init(&target, text, sizeof(text));
		result = dns_rdata_totext(&rdata, NULL, &target);
		assert_int_equal(result, ISC_R_SUCCESS);
		fprintf(stderr, "%.*s\n", (int)isc_buffer_usedlength(&target),
			text);
	}

	assert_int_equal(rdata.length, 6 + 384 / 8);
	dns_rdata_tostruct(&rdata, &zonemd, NULL);
	assert_int_equal(zonemd.serial, 2018031900);
	assert_int_equal(zonemd.scheme, DNS_ZONEMD_SCHEME_SIMPLE);
	assert_int_equal(zonemd.digest_type, DNS_ZONEMD_DIGEST_SHA384);
	assert_int_equal(zonemd.length, 384 / 8);
	assert_memory_equal(zonemd.digest,
			    "\xc6\x80\x90\xd9\x0a\x7a\xed\x71\x6b\xc4\x59\xf9"
			    "\x34\x0e\x3d\x7c\x13\x70\xd4\xd2\x4b\x7e\x2f\xc3"
			    "\xa1\xdd\xc0\xb9\xa8\x71\x53\xb9\xa9\x71\x3b\x3c"
			    "\x9a\xe5\xcc\x27\x77\x7f\x98\xb8\xe7\x30\x04\x4c",
			    zonemd.length);
	dns_rdata_reset(&rdata);
	dns_db_detach(&db);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "example",
				 "testdata/zonemd/rfc8976.A.2.db");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_zonemd_buildrdata(
		&rdata, db, NULL, DNS_ZONEMD_SCHEME_SIMPLE,
		DNS_ZONEMD_DIGEST_SHA384, mctx, buf, sizeof(buf));
	assert_int_equal(result, ISC_R_SUCCESS);

	if (debug) {
		isc_buffer_init(&target, text, sizeof(text));
		result = dns_rdata_totext(&rdata, NULL, &target);
		assert_int_equal(result, ISC_R_SUCCESS);
		fprintf(stderr, "%.*s\n", (int)isc_buffer_usedlength(&target),
			text);
	}

	assert_int_equal(rdata.length, 6 + 384 / 8);
	dns_rdata_tostruct(&rdata, &zonemd, NULL);
	assert_int_equal(zonemd.serial, 2018031900);
	assert_int_equal(zonemd.scheme, DNS_ZONEMD_SCHEME_SIMPLE);
	assert_int_equal(zonemd.digest_type, DNS_ZONEMD_DIGEST_SHA384);
	assert_int_equal(zonemd.length, 384 / 8);
	assert_memory_equal(zonemd.digest,
			    "\xa3\xb6\x9b\xad\x98\x0a\x35\x04\xe1\xcf\xfc\xb0"
			    "\xfd\x63\x97\xf9\x38\x48\x07\x1c\x93\x15\x1f\x55"
			    "\x2a\xe2\xf6\xb1\x71\x1d\x4b\xd2\xd8\xb3\x98\x08"
			    "\x22\x6d\x7b\x9d\xb7\x1e\x34\xb7\x20\x77\xf8\xfe",
			    zonemd.length);
	dns_rdata_reset(&rdata);
	dns_db_detach(&db);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "example",
				 "testdata/zonemd/rfc8976.A.3.db");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_zonemd_buildrdata(
		&rdata, db, NULL, DNS_ZONEMD_SCHEME_SIMPLE,
		DNS_ZONEMD_DIGEST_SHA384, mctx, buf, sizeof(buf));
	assert_int_equal(result, ISC_R_SUCCESS);

	if (debug) {
		isc_buffer_init(&target, text, sizeof(text));
		result = dns_rdata_totext(&rdata, NULL, &target);
		assert_int_equal(result, ISC_R_SUCCESS);
		fprintf(stderr, "%.*s\n", (int)isc_buffer_usedlength(&target),
			text);
	}

	assert_int_equal(rdata.length, 6 + 384 / 8);
	dns_rdata_tostruct(&rdata, &zonemd, NULL);
	assert_int_equal(zonemd.serial, 2018031900);
	assert_int_equal(zonemd.scheme, DNS_ZONEMD_SCHEME_SIMPLE);
	assert_int_equal(zonemd.digest_type, DNS_ZONEMD_DIGEST_SHA384);
	assert_int_equal(zonemd.length, 384 / 8);
	assert_memory_equal(zonemd.digest,
			    "\x62\xe6\xcf\x51\xb0\x2e\x54\xb9\xb5\xf9\x67\xd5"
			    "\x47\xce\x43\x13\x67\x92\x90\x1f\x9f\x88\xe6\x37"
			    "\x49\x3d\xaa\xf4\x01\xc9\x2c\x27\x9d\xd1\x0f\x0e"
			    "\xdb\x1c\x56\xf8\x08\x02\x11\xf8\x48\x0e\xe3\x06",
			    zonemd.length);
	dns_rdata_reset(&rdata);

	result = dns_zonemd_buildrdata(
		&rdata, db, NULL, DNS_ZONEMD_SCHEME_SIMPLE,
		DNS_ZONEMD_DIGEST_SHA512, mctx, buf, sizeof(buf));
	assert_int_equal(result, ISC_R_SUCCESS);

	if (debug) {
		isc_buffer_init(&target, text, sizeof(text));
		result = dns_rdata_totext(&rdata, NULL, &target);
		assert_int_equal(result, ISC_R_SUCCESS);
		fprintf(stderr, "%.*s\n", (int)isc_buffer_usedlength(&target),
			text);
	}

	assert_int_equal(rdata.length, 6 + 512 / 8);
	dns_rdata_tostruct(&rdata, &zonemd, NULL);
	assert_int_equal(zonemd.serial, 2018031900);
	assert_int_equal(zonemd.scheme, DNS_ZONEMD_SCHEME_SIMPLE);
	assert_int_equal(zonemd.digest_type, DNS_ZONEMD_DIGEST_SHA512);
	assert_int_equal(zonemd.length, 512 / 8);
	assert_memory_equal(
		zonemd.digest,
		"\x08\xcf\xa1\x11\x5c\x7b\x94\x8c\x41\x63\xa9\x01\x27\x03\x95"
		"\xea\x22\x6a\x93\x0c\xd2\xcb\xcf\x2f\xa9\xa5\xe6\xeb\x85\xf3"
		"\x7c\x8a\x4e\x11\x4d\x88\x4e\x66\xf1\x76\xea\xb1\x21\xcb\x02"
		"\xdb\x7d\x65\x2e\x0c\xc4\x82\x7e\x7a\x32\x04\xf1\x66\xb4\x7e"
		"\x56\x13\xfd\x27",
		zonemd.length);
	dns_rdata_reset(&rdata);
	dns_db_detach(&db);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "uri.arpa",
				 "testdata/zonemd/rfc8976.A.4.db");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_zonemd_buildrdata(
		&rdata, db, NULL, DNS_ZONEMD_SCHEME_SIMPLE,
		DNS_ZONEMD_DIGEST_SHA384, mctx, buf, sizeof(buf));
	assert_int_equal(result, ISC_R_SUCCESS);

	if (debug) {
		isc_buffer_init(&target, text, sizeof(text));
		result = dns_rdata_totext(&rdata, NULL, &target);
		assert_int_equal(result, ISC_R_SUCCESS);
		fprintf(stderr, "%.*s\n", (int)isc_buffer_usedlength(&target),
			text);
	}

	assert_int_equal(rdata.length, 6 + 384 / 8);
	dns_rdata_tostruct(&rdata, &zonemd, NULL);
	assert_int_equal(zonemd.serial, 2018100702);
	assert_int_equal(zonemd.scheme, DNS_ZONEMD_SCHEME_SIMPLE);
	assert_int_equal(zonemd.digest_type, DNS_ZONEMD_DIGEST_SHA384);
	assert_int_equal(zonemd.length, 384 / 8);
	assert_memory_equal(zonemd.digest,
			    "\x0d\xbc\x3c\x4d\xbf\xd7\x57\x77\xc1\x2c\xa1\x9c"
			    "\x33\x78\x54\xb1\x57\x77\x99\x90\x13\x07\xc4\x82"
			    "\xe9\xd9\x1d\x5d\x15\xcd\x93\x4d\x16\x31\x9d\x98"
			    "\xe3\x0c\x42\x01\xcf\x25\xa1\xd5\xa0\x25\x49\x60",
			    zonemd.length);
	dns_rdata_reset(&rdata);
	dns_db_detach(&db);

	result = dns_test_loaddb(&db, dns_dbtype_zone, "root-servers.net",
				 "testdata/zonemd/rfc8976.A.5.db");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_zonemd_buildrdata(
		&rdata, db, NULL, DNS_ZONEMD_SCHEME_SIMPLE,
		DNS_ZONEMD_DIGEST_SHA384, mctx, buf, sizeof(buf));
	assert_int_equal(result, ISC_R_SUCCESS);

	if (debug) {
		isc_buffer_init(&target, text, sizeof(text));
		result = dns_rdata_totext(&rdata, NULL, &target);
		assert_int_equal(result, ISC_R_SUCCESS);
		fprintf(stderr, "%.*s\n", (int)isc_buffer_usedlength(&target),
			text);
	}

	assert_int_equal(rdata.length, 6 + 384 / 8);
	dns_rdata_tostruct(&rdata, &zonemd, NULL);
	assert_int_equal(zonemd.serial, 2018091100);
	assert_int_equal(zonemd.scheme, DNS_ZONEMD_SCHEME_SIMPLE);
	assert_int_equal(zonemd.digest_type, DNS_ZONEMD_DIGEST_SHA384);
	assert_int_equal(zonemd.length, 384 / 8);
	assert_memory_equal(zonemd.digest,
			    "\xf1\xca\x0c\xcd\x91\xbd\x55\x73\xd9\xf4\x31\xc0"
			    "\x0e\xe0\x10\x1b\x25\x45\xc9\x76\x02\xbe\x0a\x97"
			    "\x8a\x3b\x11\xdb\xfc\x1c\x77\x6d\x5b\x3e\x86\xae"
			    "\x3d\x97\x3d\x6b\x53\x49\xba\x7f\x04\x34\x0f\x79",
			    zonemd.length);
	dns_rdata_reset(&rdata);
	dns_db_detach(&db);

	isc_mem_detach(&mctx);
}

int
main(int argc, char **argv) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(zonemd_buildrdata),
	};
	struct CMUnitTest selected[sizeof(tests) / sizeof(tests[0])];
	size_t i;
	int c;

	memset(selected, 0, sizeof(selected));

	while ((c = isc_commandline_parse(argc, argv, "dlt:")) != -1) {
		switch (c) {
		case 'd':
			debug = true;
			break;
		case 'l':
			for (i = 0; i < (sizeof(tests) / sizeof(tests[0])); i++)
			{
				if (tests[i].name != NULL) {
					fprintf(stdout, "%s\n", tests[i].name);
				}
			}
			return (0);
		case 't':
			if (!cmocka_add_test_byname(
				    tests, isc_commandline_argument, selected))
			{
				fprintf(stderr, "unknown test '%s'\n",
					isc_commandline_argument);
				exit(1);
			}
			break;
		default:
			break;
		}
	}

	if (selected[0].name != NULL) {
		return (cmocka_run_group_tests(selected, _setup, _teardown));
	} else {
		return (cmocka_run_group_tests(tests, _setup, _teardown));
	}
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
