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

#define ISC_ZONEMD_DEBUG

#include <isc/md.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>
#include <dns/zonemd.h>

#define CHECK(r)                             \
	do {                                 \
		result = (r);                \
		if (result != ISC_R_SUCCESS) \
			goto cleanup;        \
	} while (0)

static isc_result_t
digest_callback(void *arg, isc_region_t *data) {
#ifdef ISC_ZONEMD_DEBUG
	unsigned int j;
	for (j = 0; j < data->length; j++) {
		fprintf(stderr, "%02x", data->base[j]);
	}
#endif
	return (isc_md_update(arg, data->base, data->length));
}

static isc_result_t
digest_rdataset(dns_name_t *name, dns_rdataset_t *rds, isc_mem_t *mctx,
		isc_md_t *md) {
	dns_fixedname_t fixed;
	isc_region_t r;
	char data[256 + 8];
	isc_buffer_t envbuf;
	isc_result_t result;
	dns_rdata_t *rdatas = NULL;
	unsigned int i, nrdatas;
#ifdef ISC_ZONEMD_DEBUG
	char namebuf[DNS_NAME_FORMATSIZE];
#endif

	dns_fixedname_init(&fixed);
	RUNTIME_CHECK(dns_name_downcase(name, dns_fixedname_name(&fixed),
					NULL) == ISC_R_SUCCESS);
	dns_name_toregion(dns_fixedname_name(&fixed), &r);
#ifdef ISC_ZONEMD_DEBUG
	dns_name_format(dns_fixedname_name(&fixed), namebuf, sizeof(namebuf));
#endif

	/*
	 * Create an envelope for each rdata: <name|type|class|ttl>.
	 */
	isc_buffer_init(&envbuf, data, sizeof(data));
	memmove(data, r.base, r.length);
	isc_buffer_add(&envbuf, r.length);
	isc_buffer_putuint16(&envbuf, rds->type);
	isc_buffer_putuint16(&envbuf, rds->rdclass);
	isc_buffer_putuint32(&envbuf, rds->ttl);

	CHECK(dns_rdataset_tosortedarray(rds, mctx, &rdatas, &nrdatas));

	isc_buffer_usedregion(&envbuf, &r);

	for (i = 0; i < nrdatas; i++) {
		unsigned char len[2];

		/*
		 * Skip duplicates.
		 */
		if (i > 0 && dns_rdata_compare(&rdatas[i], &rdatas[i - 1]) == 0)
		{
			continue;
		}

		/*
		 * Digest the envelope.
		 */
		CHECK(isc_md_update(md, r.base, r.length));

		/*
		 * Digest the length of the rdata.
		 */
		INSIST(rdatas[i].length < 65536);
		len[0] = rdatas[i].length >> 8;
		len[1] = rdatas[i].length & 0xff;
		CHECK(isc_md_update(md, len, 2));

#ifdef ISC_ZONEMD_DEBUG
		isc_buffer_t b;
		char rdatabuf[65 * 1024];
		unsigned int j;
		isc_buffer_init(&b, rdatabuf, sizeof(rdatabuf));
		dns_rdata_totext(&rdatas[i], NULL, &b);
		fprintf(stderr,
			"digest %s type=%u class=%u ttl=%u rdlen=%u %.*s\n",
			namebuf, rds->type, rds->rdclass, rds->ttl,
			rdatas[i].length, (int)isc_buffer_usedlength(&b),
			rdatabuf);
		fprintf(stderr, "DIGEST:");
		for (j = 0; j < r.length; j++) {
			fprintf(stderr, "%02x", r.base[j]);
		}
		fprintf(stderr, "%02x%02x", len[0], len[1]);
#endif
		/*
		 * Digest the rdata.
		 */
		CHECK(dns_rdata_digest(&rdatas[i], digest_callback, md));
#ifdef ISC_ZONEMD_DEBUG
		fprintf(stderr, "\n");
#endif
	}

cleanup:
	if (rdatas != NULL) {
		isc_mem_put(mctx, rdatas, nrdatas * sizeof(*rdatas));
	}

	return (result);
}

static isc_result_t
get_serial(dns_rdataset_t *rds, unsigned char *buf) {
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_soa_t soa;
	isc_result_t result;

	CHECK(dns_rdataset_first(rds));
	dns_rdataset_current(rds, &rdata);
	CHECK(dns_rdata_tostruct(&rdata, &soa, NULL));
	buf[0] = (soa.serial >> 24) & 0xff;
	buf[1] = (soa.serial >> 16) & 0xff;
	buf[2] = (soa.serial >> 8) & 0xff;
	buf[3] = (soa.serial >> 0) & 0xff;
cleanup:
	return (result);
}

static isc_result_t
process_name(dns_db_t *db, dns_dbversion_t *version, dns_name_t *name,
	     dns_dbnode_t *nsecnode, dns_dbnode_t *nsec3node, isc_mem_t *mctx,
	     unsigned char *buf, isc_md_t *md, bool *seen_soa) {
	dns_rdataset_t rds[20];
	dns_rdatasetiter_t *nseciter = NULL;
	dns_rdatasetiter_t *nsec3iter = NULL;
	dns_rdatatype_t best = 0, covers = 0;
	isc_result_t result;
	size_t i, j;
	bool again = true;
	bool best_set = false;
	bool covers_set = false;

	char namebuf[DNS_NAME_FORMATSIZE];
	dns_name_format(name, namebuf, sizeof(namebuf));

	if (!dns_name_issubdomain(name, dns_db_origin(db))) {
#ifdef ISC_ZONEMD_DEBUG
		fprintf(stderr, "skipping %s out-of-zone\n", namebuf);
#endif
		return (ISC_R_SUCCESS);
	}

	for (i = 0; i < ARRAY_SIZE(rds); i++) {
		dns_rdataset_init(&rds[i]);
	}

	if (nsecnode != NULL) {
		CHECK(dns_db_allrdatasets(db, nsecnode, version, 0, &nseciter));
	}
	if (nsec3node != NULL) {
		CHECK(dns_db_allrdatasets(db, nsec3node, version, 0,
					  &nsec3iter));
	}

	while (again) {
		again = false;
		i = 0;

		if (nseciter != NULL) {
			result = dns_rdatasetiter_first(nseciter);
		} else {
			result = ISC_R_NOMORE;
		}
		while (result == ISC_R_SUCCESS) {
			/*
			 * Don't digest ZONEMD or RRSIG(ZONEMD).
			 */
			dns_rdatasetiter_current(nseciter, &rds[i]);
#ifdef ISC_ZONEMD_DEBUG
			fprintf(stderr, "looking at %s %u/%u\n", namebuf,
				rds[i].type, rds[i].covers);
#endif
			if ((rds[i].type == dns_rdatatype_zonemd ||
			     (rds[i].type == dns_rdatatype_rrsig &&
			      rds[i].covers == dns_rdatatype_zonemd)) &&
			    dns_name_equal(name, dns_db_origin(db)))
			{
#ifdef ISC_ZONEMD_DEBUG
				fprintf(stderr, "skipping apex zonemd / "
						"RRSIG(zonemd)\n");
#endif
				dns_rdataset_disassociate(&rds[i]);
				goto nsecskip;
			}
			if ((covers_set && rds[i].type == dns_rdatatype_rrsig &&
			     rds[i].covers <= covers) ||
			    (best_set && rds[i].type != dns_rdatatype_rrsig &&
			     rds[i].type <= best))
			{
#ifdef ISC_ZONEMD_DEBUG
				fprintf(stderr,
					"skipping (already processed)\n");
#endif
				dns_rdataset_disassociate(&rds[i]);
				goto nsecskip;
			}
			/*
			 * Note RRSIG COVERED is the first field so multiple
			 * RRSIG RRsets can be sorted by their COVERED field.
			 */
			for (j = 0; j < i; j++) {
				if ((rds[i].type < rds[j].type ||
				     (rds[j].type == dns_rdatatype_rrsig &&
				      rds[i].type == dns_rdatatype_rrsig &&
				      rds[i].covers < rds[j].covers)))
				{
					dns_rdataset_t tmp = rds[j];
					rds[j] = rds[i];
					rds[i] = tmp;
				}
			}
			if (i == ARRAY_SIZE(rds) - 1 &&
			    dns_rdataset_isassociated(&rds[i])) {
				dns_rdataset_disassociate(&rds[i]);
				again = true;
			} else {
				i++;
			}
		nsecskip:
			result = dns_rdatasetiter_next(nseciter);
		}

		if (result == ISC_R_NOMORE && nsec3iter != NULL) {
			result = dns_rdatasetiter_first(nsec3iter);
		}
		while (result == ISC_R_SUCCESS) {
			/*
			 * Don't digest ZONEMD or RRSIG(ZONEMD).
			 */
			dns_rdatasetiter_current(nsec3iter, &rds[i]);
#ifdef ISC_ZONEMD_DEBUG
			fprintf(stderr, "looking at %s %u/%u\n", namebuf,
				rds[i].type, rds[i].covers);
#endif
			if ((covers_set && rds[i].type == dns_rdatatype_rrsig &&
			     rds[i].covers <= covers) ||
			    (best_set && rds[i].type != dns_rdatatype_rrsig &&
			     rds[i].type <= best))
			{
#ifdef ISC_ZONEMD_DEBUG
				fprintf(stderr,
					"skipping (already processed)\n");
#endif
				dns_rdataset_disassociate(&rds[i]);
				goto nsec3skip;
			}
			/*
			 * Note RRSIG COVERED is the first field so multiple
			 * RRSIG RRsets can be sorted by their COVERED field.
			 */
			for (j = 0; j < i; j++) {
				if ((rds[i].type < rds[j].type ||
				     (rds[j].type == dns_rdatatype_rrsig &&
				      rds[i].type == dns_rdatatype_rrsig &&
				      rds[i].covers < rds[j].covers)))
				{
					dns_rdataset_t tmp = rds[j];
					rds[j] = rds[i];
					rds[i] = tmp;
				}
			}
			if (i == ARRAY_SIZE(rds) - 1 &&
			    dns_rdataset_isassociated(&rds[i])) {
				dns_rdataset_disassociate(&rds[i]);
				again = true;
			} else {
				i++;
			}
		nsec3skip:
			result = dns_rdatasetiter_next(nsec3iter);
		}

		/*
		 * Digest the selected set of records.
		 */
		if (result == ISC_R_NOMORE) {
			for (j = 0; j < i; j++) {
				if (rds[j].type == dns_rdatatype_soa &&
				    dns_name_equal(name, dns_db_origin(db))) {
					CHECK(get_serial(&rds[j], buf));
					*seen_soa = true;
				}
				CHECK(digest_rdataset(name, &rds[j], mctx, md));
				best = rds[j].type;
				best_set = true;
				if (rds[j].type == dns_rdatatype_rrsig) {
					covers = rds[j].covers;
					covers_set = true;
				}
				dns_rdataset_disassociate(&rds[j]);
			}
			if (dns_rdataset_isassociated(&rds[i])) {
				if (!again) {
					CHECK(digest_rdataset(name, &rds[i],
							      mctx, md));
				}
				dns_rdataset_disassociate(&rds[i]);
			}
			result = ISC_R_SUCCESS;
		}
	}
cleanup:
	for (i = 0; i < ARRAY_SIZE(rds); i++) {
		if (dns_rdataset_isassociated(&rds[i])) {
			dns_rdataset_disassociate(&rds[i]);
		}
	}
	if (nseciter != NULL) {
		dns_rdatasetiter_destroy(&nseciter);
	}
	if (nsec3iter != NULL) {
		dns_rdatasetiter_destroy(&nsec3iter);
	}
	return (result);
}

static isc_result_t
zonemd_simple(dns_rdata_t *rdata, dns_db_t *db, dns_dbversion_t *version,
	      uint8_t algorithm, isc_mem_t *mctx, unsigned char *buf,
	      size_t size) {
	bool seen_soa = false;
	dns_dbiterator_t *nsecdbiter = NULL;
	dns_dbiterator_t *nsec3dbiter = NULL;
	dns_dbnode_t *nsecnode = NULL;
	dns_dbnode_t *nsec3node = NULL;
	dns_fixedname_t nsecfixed;
	dns_fixedname_t nsec3fixed;
	dns_name_t *nsecname;
	dns_name_t *nsec3name;
	isc_md_t *md = isc_md_new();
	isc_result_t result, nsecresult, nsec3result;
	isc_region_t r;

	if (md == NULL) {
		CHECK(ISC_R_NOMEMORY);
	}
	switch (algorithm) {
	case DNS_ZONEMD_DIGEST_SHA384:
		if (size < ISC_SHA384_DIGESTLENGTH + 6) {
			CHECK(ISC_R_NOSPACE);
		}
		r.base = buf;
		r.length = ISC_SHA384_DIGESTLENGTH + 6;
		CHECK(isc_md_init(md, ISC_MD_SHA384));
		break;
	case DNS_ZONEMD_DIGEST_SHA512:
		if (size < ISC_SHA512_DIGESTLENGTH + 6) {
			CHECK(ISC_R_NOSPACE);
		}
		r.base = buf;
		r.length = ISC_SHA512_DIGESTLENGTH + 6;
		CHECK(isc_md_init(md, ISC_MD_SHA512));
		break;
	default:
		CHECK(ISC_R_NOTIMPLEMENTED);
	}
	dns_fixedname_init(&nsecfixed);
	dns_fixedname_init(&nsec3fixed);
	CHECK(dns_db_createiterator(db, DNS_DB_NONSEC3, &nsecdbiter));
	CHECK(dns_db_createiterator(db, DNS_DB_NSEC3ONLY, &nsec3dbiter));
	nsecresult = dns_dbiterator_first(nsecdbiter);
	nsec3result = dns_dbiterator_first(nsec3dbiter);
	while (nsecresult == ISC_R_SUCCESS || nsec3result == ISC_R_SUCCESS) {
		if (nsecresult == ISC_R_SUCCESS) {
			nsecname = dns_fixedname_name(&nsecfixed);
			CHECK(dns_dbiterator_current(nsecdbiter, &nsecnode,
						     nsecname));
			dns_dbiterator_pause(nsecdbiter);
		} else {
			nsecname = NULL;
		}
		if (nsec3result == ISC_R_SUCCESS) {
			nsec3name = dns_fixedname_name(&nsec3fixed);
			CHECK(dns_dbiterator_current(nsec3dbiter, &nsec3node,
						     nsec3name));
			dns_dbiterator_pause(nsec3dbiter);
		} else {
			nsec3name = NULL;
		}
		/*
		 * Workout which name / node to process next.
		 */
		if (nsecname != NULL && nsec3name != NULL) {
			int n = dns_name_compare(nsecname, nsec3name);
			if (n < 0) {
				nsec3name = NULL;
				if (nsec3node != NULL) {
					dns_db_detachnode(db, &nsec3node);
				}
			}
			if (n > 0) {
				nsecname = NULL;
				if (nsecnode != NULL) {
					dns_db_detachnode(db, &nsecnode);
				}
			}
		}
		CHECK(process_name(
			db, version, nsecname != NULL ? nsecname : nsec3name,
			nsecnode, nsec3node, mctx, buf, md, &seen_soa));
		if (nsecnode != NULL) {
			dns_db_detachnode(db, &nsecnode);
		}
		if (nsec3node != NULL) {
			dns_db_detachnode(db, &nsec3node);
		}
		if (nsecname != NULL) {
			nsecresult = dns_dbiterator_next(nsecdbiter);
		}
		if (nsec3name != NULL) {
			nsec3result = dns_dbiterator_next(nsec3dbiter);
		}
	}
	if (nsecresult == ISC_R_NOMORE && nsec3result == ISC_R_NOMORE) {
		unsigned int len = size - 6;
		buf[4] = 1;
		buf[5] = algorithm;
		CHECK(isc_md_final(md, buf + 6, &len));
		if (!seen_soa) {
			CHECK(DNS_R_BADZONE);
		}
		if (len + 6 != r.length) {
			CHECK(ISC_R_FAILURE);
		}
		if (rdata != NULL) {
			dns_rdata_fromregion(rdata, dns_db_class(db),
					     dns_rdatatype_zonemd, &r);
		}
	} else {
		result = nsecresult != ISC_R_NOMORE ? nsecresult : nsec3result;
	}

cleanup:
	if (md != NULL) {
		isc_md_free(md);
	}
	if (nsecnode != NULL) {
		dns_db_detachnode(db, &nsecnode);
	}
	if (nsec3node != NULL) {
		dns_db_detachnode(db, &nsec3node);
	}
	if (nsecdbiter != NULL) {
		dns_dbiterator_destroy(&nsecdbiter);
	}
	if (nsec3dbiter != NULL) {
		dns_dbiterator_destroy(&nsec3dbiter);
	}
	return (result);
}

isc_result_t
dns_zonemd_buildrdata(dns_rdata_t *rdata, dns_db_t *db,
		      dns_dbversion_t *version, uint8_t scheme,
		      uint8_t algorithm, isc_mem_t *mctx, unsigned char *buf,
		      size_t size) {
	REQUIRE(db != NULL);
	REQUIRE(buf != NULL);

	/*
	 * Check for supported scheme/algorithm combinations.
	 */
	switch (scheme) {
	case DNS_ZONEMD_SCHEME_SIMPLE:
		switch (algorithm) {
		case DNS_ZONEMD_DIGEST_SHA384:
		case DNS_ZONEMD_DIGEST_SHA512:
			break;
		default:
			return (ISC_R_NOTIMPLEMENTED);
		}
		return (zonemd_simple(rdata, db, version, algorithm, mctx, buf,
				      size));
		break;
	default:
		return (ISC_R_NOTIMPLEMENTED);
	}
}
