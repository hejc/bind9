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

#include <dns/types.h>

#define DNS_ZONEMD_BUFFERSIZE (6U + 64U)

isc_result_t
dns_zonemd_buildrdata(dns_rdata_t *rdata, dns_db_t *db,
		      dns_dbversion_t *version, uint8_t scheme,
		      uint8_t algorithm, isc_mem_t *mctx, unsigned char *buf,
		      size_t size);

bool
dns_zonemd_supported(dns_rdata_t *rdata);
