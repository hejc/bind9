#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# The script investigates test-suite.log and systests.output files and prints
# the number of core dumps, assertion failures, and ThreadSanitizer reports
# identified.
#
# Usage:
#    testsummary.sh
#
# Status return:
# 0 - no tests failed
# 1 - one or more tests failed

# shellcheck source=conf.sh
. ./conf.sh

status=0

TEST_FILE=test-suite.log
if [ "$(find . -name 'test.output.*' 2>/dev/null | wc -l)" -gt 0 ]; then
    cat test.output.* > systests.output
    TEST_FILE=systests.output
fi

if [ ! -s "${TEST_FILE}" ]; then
    echowarn "I:File ${TEST_FILE} was not found."
    exit 1
fi

echoinfo "I:System test result summary:"
if [ "${TEST_FILE}" = systests.output ]; then
    echoinfo "$(grep 'R:[a-z0-9_-][a-z0-9_-]*:[A-Z][A-Z]*' "${TEST_FILE}" | cut -d':' -f3 | sort | uniq -c | sed -e 's/^/I:/')"
else
    echoinfo "$(sed -ne '/^# /s/^# //p' "${TEST_FILE}" | sed -e 's/^/I:      /')"
fi

FAILED_TESTS=$(grep 'R:[a-z0-9_-][a-z0-9_-]*:FAIL' "${TEST_FILE}" | cut -d':' -f2 | sort | sed -e 's/^/I:      /')
if [ -n "${FAILED_TESTS}" ]; then
       echoinfo "I:The following system tests failed:"
       echoinfo "${FAILED_TESTS}"
       status=1
fi

CRASHED_TESTS=$(awk -F: '/I:.*:Core dump\(s\) found/ { print $2 }' "${TEST_FILE}" | sort -u | sed -e 's/^/I:      /')
if [ -n "${CRASHED_TESTS}" ]; then
	echoinfo "I:Core dumps were found for the following system tests:"
	echoinfo "${CRASHED_TESTS}"
	status=1
fi

ASSERTION_FAILED_TESTS=$(awk -F: '/I:.*:.*assertion failure\(s\) found/ { print $2 }' "${TEST_FILE}" | sort -u | sed -e 's/^/I:      /')
if [ -n "${ASSERTION_FAILED_TESTS}" ]; then
	echoinfo "I:Assertion failures were detected for the following system tests:"
	echoinfo "${ASSERTION_FAILED_TESTS}"
	status=1
fi

TSAN_REPORT_TESTS=$(awk -F: '/I:.*:.*sanitizer report\(s\) found/ { print $2 }' "${TEST_FILE}" | sort -u | sed -e 's/^/I:      /')
if [ -n "${TSAN_REPORT_TESTS}" ]; then
	echoinfo "I:ThreadSanitizer reported issues for the following system tests:"
	echoinfo "${TSAN_REPORT_TESTS}"
	status=1
fi

exit $status
