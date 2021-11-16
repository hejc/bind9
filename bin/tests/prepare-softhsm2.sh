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

if [ -n "${SOFTHSM2_CONF}" ] && command -v softhsm2-util >/dev/null; then
    SOFTHSM2_DIR=$(dirname "$SOFTHSM2_CONF")
    mkdir -p "${SOFTHSM2_DIR}/tokens"
    echo "directories.tokendir = ${SOFTHSM2_DIR}/tokens" > "${SOFTHSM2_CONF}"
    echo "objectstore.backend = file" >> "${SOFTHSM2_CONF}"
    echo "log.level = DEBUG" >> "${SOFTHSM2_CONF}"
fi
exit 0
