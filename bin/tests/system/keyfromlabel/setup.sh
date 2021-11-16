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

# shellcheck source=conf.sh
. ../conf.sh

set -e

if [ -z "$SOFTHSM2_CONF" ] ; then
	echo_i "softhsm2 configuration not set, required for test"
	exit 1
fi

if [ -z "$SOFTHSM2_MODULE" ] ; then
	echo_i "softhsm2 module not set, required for test"
	exit 1
fi

if [ -z "$OPENSSL_ENGINES" ] ; then
	echo_i "openssl engines path not set, required for test"
	exit 1
fi

echo_i "softhsm settings:"
echo_i "openssl conf: $OPENSSL_CONF"
echo_i "openssl engines: $OPENSSL_ENGINES"
echo_i "softhsm conf: $SOFTHSM2_CONF"
echo_i "softhsm module: $SOFTHSM2_MODULE"

softhsm2-util --show-slots

printf '%s' "${HSMPIN:-1234}" > pin
PWD=$(pwd)
