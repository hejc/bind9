#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

. ../conf.sh

copy_setports ns1/named.conf.in ns1/named.conf
copy_setports ns2/named.conf.in ns2/named.conf
copy_setports ns5/named.conf.in ns5/named.conf
copy_setports ns7/named.conf.in ns7/named.conf

cd ns2
$SHELL sign.sh
