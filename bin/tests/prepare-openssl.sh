#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Installing OpenSC/libp11
git clone https://github.com/OpenSC/libp11.git /var/tmp/libp11
cd /var/tmp/libp11
./bootstrap
./configure --with-enginesdir="${OPENSSL_ENGINES}"
make
make install
ldconfig

# Configuring OpenSSL
OPENSSL_DIR=$(dirname "$OPENSSL_CONF")
mkdir -p "${OPENSSL_DIR}"
(
	echo "openssl_conf = openssl_init"
	grep -v "^openssl_conf = " "${DEFAULT_OPENSSL_CONF}"
	cat <<EOF

[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = "${OPENSSL_ENGINES}/pkcs11.so"
MODULE_PATH = "${SOFTHSM2_MODULE}"
init = 0
EOF
) > "${OPENSSL_CONF}"

exit 0
