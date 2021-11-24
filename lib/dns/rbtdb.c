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

/*! \file */

/* #define inline */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/mman.h>

#include <isc/atomic.h>
#include <isc/crc64.h>
#include <isc/event.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/heap.h>
#include <isc/hex.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/serial.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/events.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/masterdump.h>
#include <dns/nsec.h>
#include <dns/nsec3.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdataslab.h>
#include <dns/rdatastruct.h>
#include <dns/stats.h>
#include <dns/time.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zonekey.h>

#include "rbtdb.h"

#define RBTDB_MAGIC ISC_MAGIC('R', 'B', 'D', '4')

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define VALID_RBTDB(rbtdb) \
	((rbtdb) != NULL && (rbtdb)->common.impmagic == RBTDB_MAGIC)

typedef uint32_t rbtdb_serial_t;
typedef uint32_t rbtdb_rdatatype_t;

#define RBTDB_RDATATYPE_BASE(type) ((dns_rdatatype_t)((type)&0xFFFF))
#define RBTDB_RDATATYPE_EXT(type)  ((dns_rdatatype_t)((type) >> 16))
#define RBTDB_RDATATYPE_VALUE(base, ext)              \
	((rbtdb_rdatatype_t)(((uint32_t)ext) << 16) | \
	 (((uint32_t)base) & 0xffff))

#define RBTDB_RDATATYPE_SIGNSEC \
	RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, dns_rdatatype_nsec)
#define RBTDB_RDATATYPE_SIGNSEC3 \
	RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, dns_rdatatype_nsec3)
#define RBTDB_RDATATYPE_SIGNS \
	RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, dns_rdatatype_ns)
#define RBTDB_RDATATYPE_SIGCNAME \
	RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, dns_rdatatype_cname)
#define RBTDB_RDATATYPE_SIGDNAME \
	RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, dns_rdatatype_dname)
#define RBTDB_RDATATYPE_SIGDS \
	RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, dns_rdatatype_ds)
#define RBTDB_RDATATYPE_SIGSOA \
	RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, dns_rdatatype_soa)
#define RBTDB_RDATATYPE_NCACHEANY RBTDB_RDATATYPE_VALUE(0, dns_rdatatype_any)

#define RBTDB_INITLOCK(l)    isc_rwlock_init((l), 0, 0)
#define RBTDB_DESTROYLOCK(l) isc_rwlock_destroy(l)
#define RBTDB_LOCK(l, t)     RWLOCK((l), (t))
#define RBTDB_UNLOCK(l, t)   RWUNLOCK((l), (t))

/*
 * Since node locking is sensitive to both performance and memory footprint,
 * we need some trick here.  If we have both high-performance rwlock and
 * high performance and small-memory reference counters, we use rwlock for
 * node lock and isc_refcount for node references.  In this case, we don't have
 * to protect the access to the counters by locks.
 * Otherwise, we simply use ordinary mutex lock for node locking, and use
 * simple integers as reference counters which is protected by the lock.
 * In most cases, we can simply use wrapper macros such as NODE_LOCK and
 * NODE_UNLOCK.  In some other cases, however, we need to protect reference
 * counters first and then protect other parts of a node as read-only data.
 * Special additional macros, NODE_STRONGLOCK(), NODE_WEAKLOCK(), etc, are also
 * provided for these special cases.  When we can use the efficient backend
 * routines, we should only protect the "other members" by NODE_WEAKLOCK(read).
 * Otherwise, we should use NODE_STRONGLOCK() to protect the entire critical
 * section including the access to the reference counter.
 * Note that we cannot use NODE_LOCK()/NODE_UNLOCK() wherever the protected
 * section is also protected by NODE_STRONGLOCK().
 */
typedef isc_rwlock_t nodelock_t;

#define NODE_INITLOCK(l)    isc_rwlock_init((l), 0, 0)
#define NODE_DESTROYLOCK(l) isc_rwlock_destroy(l)
#define NODE_LOCK(l, t)	    RWLOCK((l), (t))
#define NODE_UNLOCK(l, t)   RWUNLOCK((l), (t))
#define NODE_TRYUPGRADE(l)  isc_rwlock_tryupgrade(l)
#define NODE_DOWNGRADE(l)   isc_rwlock_downgrade(l)

/*%
 * Whether to rate-limit updating the LRU to avoid possible thread contention.
 * Updating LRU requires write locking, so we don't do it every time the
 * record is touched - only after some time passes.
 */
#ifndef DNS_RBTDB_LIMITLRUUPDATE
#define DNS_RBTDB_LIMITLRUUPDATE 1
#endif

/*% Time after which we update LRU for glue records, 5 minutes */
#define DNS_RBTDB_LRUUPDATE_GLUE 300
/*% Time after which we update LRU for all other records, 10 minutes */
#define DNS_RBTDB_LRUUPDATE_REGULAR 600

/*
 * Allow clients with a virtual time of up to 5 minutes in the past to see
 * records that would have otherwise have expired.
 */
#define RBTDB_VIRTUAL 300

struct noqname {
	dns_name_t name;
	void *neg;
	void *negsig;
	dns_rdatatype_t type;
};

typedef struct rdatasetheader {
	/*%
	 * Locked by the owning node's lock.
	 */
	rbtdb_serial_t serial;
	dns_ttl_t rdh_ttl;
	rbtdb_rdatatype_t type;
	atomic_uint_least16_t attributes;
	dns_trust_t trust;
	atomic_uint_fast32_t last_refresh_fail_ts;
	struct noqname *noqname;
	struct noqname *closest;
	unsigned int resign_lsb : 1;
	/*%<
	 * We don't use the LIST macros, because the LIST structure has
	 * both head and tail pointers, and is doubly linked.
	 */

	struct rdatasetheader *next;
	/*%<
	 * If this is the top header for an rdataset, 'next' points
	 * to the top header for the next rdataset (i.e., the next type).
	 * Otherwise, it points up to the header whose down pointer points
	 * at this header.
	 */

	struct rdatasetheader *down;
	/*%<
	 * Points to the header for the next older version of
	 * this rdataset.
	 */

	atomic_uint_fast32_t count;
	/*%<
	 * Monotonously increased every time this rdataset is bound so that
	 * it is used as the base of the starting point in DNS responses
	 * when the "cyclic" rrset-order is required.
	 */

	dns_rbtnode_t *node;
	isc_stdtime_t last_used;
	ISC_LINK(struct rdatasetheader) link;

	unsigned int heap_index;
	/*%<
	 * Used for TTL-based cache cleaning.
	 */
	isc_stdtime_t resign;
	/*%<
	 * Case vector.  If the bit is set then the corresponding
	 * character in the owner name needs to be AND'd with 0x20,
	 * rendering that character upper case.
	 */
	unsigned char upper[32];
} rdatasetheader_t;

typedef ISC_LIST(rdatasetheader_t) rdatasetheaderlist_t;
typedef ISC_LIST(dns_rbtnode_t) rbtnodelist_t;

#define RDATASET_ATTR_NONEXISTENT 0x0001
/*%< May be potentially served as stale data. */
#define RDATASET_ATTR_STALE	     0x0002
#define RDATASET_ATTR_IGNORE	     0x0004
#define RDATASET_ATTR_RETAIN	     0x0008
#define RDATASET_ATTR_NXDOMAIN	     0x0010
#define RDATASET_ATTR_RESIGN	     0x0020
#define RDATASET_ATTR_STATCOUNT	     0x0040
#define RDATASET_ATTR_OPTOUT	     0x0080
#define RDATASET_ATTR_NEGATIVE	     0x0100
#define RDATASET_ATTR_PREFETCH	     0x0200
#define RDATASET_ATTR_CASESET	     0x0400
#define RDATASET_ATTR_ZEROTTL	     0x0800
#define RDATASET_ATTR_CASEFULLYLOWER 0x1000
/*%< Ancient - awaiting cleanup. */
#define RDATASET_ATTR_ANCIENT	   0x2000
#define RDATASET_ATTR_STALE_WINDOW 0x4000

/*
 * XXX
 * When the cache will pre-expire data (due to memory low or other
 * situations) before the rdataset's TTL has expired, it MUST
 * respect the RETAIN bit and not expire the data until its TTL is
 * expired.
 */

#define EXISTS(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_NONEXISTENT) == 0)
#define NONEXISTENT(header)                            \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_NONEXISTENT) != 0)
#define IGNORE(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_IGNORE) != 0)
#define RETAIN(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_RETAIN) != 0)
#define NXDOMAIN(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_NXDOMAIN) != 0)
#define STALE(header)                                                          \
	((atomic_load_acquire(&(header)->attributes) & RDATASET_ATTR_STALE) != \
	 0)
#define STALE_WINDOW(header)                           \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_STALE_WINDOW) != 0)
#define RESIGN(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_RESIGN) != 0)
#define OPTOUT(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_OPTOUT) != 0)
#define NEGATIVE(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_NEGATIVE) != 0)
#define PREFETCH(header)                               \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_PREFETCH) != 0)
#define CASESET(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_CASESET) != 0)
#define ZEROTTL(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_ZEROTTL) != 0)
#define CASEFULLYLOWER(header)                         \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_CASEFULLYLOWER) != 0)
#define ANCIENT(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_ANCIENT) != 0)
#define STATCOUNT(header)                              \
	((atomic_load_acquire(&(header)->attributes) & \
	  RDATASET_ATTR_STATCOUNT) != 0)

#define RDATASET_ATTR_GET(header, attribute) \
	(atomic_load_acquire(&(header)->attributes) & attribute)
#define RDATASET_ATTR_SET(header, attribute) \
	atomic_fetch_or_release(&(header)->attributes, attribute)
#define RDATASET_ATTR_CLR(header, attribute) \
	atomic_fetch_and_release(&(header)->attributes, ~(attribute))

#define ACTIVE(header, now)             \
	(((header)->rdh_ttl > (now)) || \
	 ((header)->rdh_ttl == (now) && ZEROTTL(header)))

#define DEFAULT_NODE_LOCK_COUNT	    7 /*%< Should be prime. */
#define RBTDB_GLUE_TABLE_INIT_BITS  2U
#define RBTDB_GLUE_TABLE_MAX_BITS   32U
#define RBTDB_GLUE_TABLE_OVERCOMMIT 3

#define GOLDEN_RATIO_32 0x61C88647
#define HASHSIZE(bits)	(UINT64_C(1) << (bits))

/*%
 * Number of buckets for cache DB entries (locks, LRU lists, TTL heaps).
 * There is a tradeoff issue about configuring this value: if this is too
 * small, it may cause heavier contention between threads; if this is too large,
 * LRU purge algorithm won't work well (entries tend to be purged prematurely).
 * The default value should work well for most environments, but this can
 * also be configurable at compilation time via the
 * DNS_RBTDB_CACHE_NODE_LOCK_COUNT variable.  This value must be larger than
 * 1 due to the assumption of overmem_purge().
 */
#ifdef DNS_RBTDB_CACHE_NODE_LOCK_COUNT
#if DNS_RBTDB_CACHE_NODE_LOCK_COUNT <= 1
#error "DNS_RBTDB_CACHE_NODE_LOCK_COUNT must be larger than 1"
#else /* if DNS_RBTDB_CACHE_NODE_LOCK_COUNT <= 1 */
#define DEFAULT_CACHE_NODE_LOCK_COUNT DNS_RBTDB_CACHE_NODE_LOCK_COUNT
#endif /* if DNS_RBTDB_CACHE_NODE_LOCK_COUNT <= 1 */
#else  /* ifdef DNS_RBTDB_CACHE_NODE_LOCK_COUNT */
#define DEFAULT_CACHE_NODE_LOCK_COUNT 17
#endif /* DNS_RBTDB_CACHE_NODE_LOCK_COUNT */

typedef struct {
	nodelock_t lock;
	/* Protected in the refcount routines. */
	isc_refcount_t references;
	/* Locked by lock. */
	bool exiting;
} rbtdb_nodelock_t;

typedef struct rbtdb_changed {
	dns_rbtnode_t *node;
	bool dirty;
	ISC_LINK(struct rbtdb_changed) link;
} rbtdb_changed_t;

typedef ISC_LIST(rbtdb_changed_t) rbtdb_changedlist_t;

typedef enum { dns_db_insecure, dns_db_partial, dns_db_secure } dns_db_secure_t;

typedef struct dns_rbtdb dns_rbtdb_t;

/* Reason for expiring a record from cache */
typedef enum { expire_lru, expire_ttl, expire_flush } expire_t;

typedef struct rbtdb_glue rbtdb_glue_t;

typedef struct rbtdb_glue_table_node {
	struct rbtdb_glue_table_node *next;
	dns_rbtnode_t *node;
	rbtdb_glue_t *glue_list;
} rbtdb_glue_table_node_t;

typedef enum {
	rdataset_ttl_fresh,
	rdataset_ttl_stale,
	rdataset_ttl_ancient
} rdataset_ttl_t;

typedef struct rbtdb_version {
	/* Not locked */
	rbtdb_serial_t serial;
	dns_rbtdb_t *rbtdb;
	/*
	 * Protected in the refcount routines.
	 * XXXJT: should we change the lock policy based on the refcount
	 * performance?
	 */
	isc_refcount_t references;
	/* Locked by database lock. */
	bool writer;
	bool commit_ok;
	rbtdb_changedlist_t changed_list;
	rdatasetheaderlist_t resigned_list;
	ISC_LINK(struct rbtdb_version) link;
	dns_db_secure_t secure;
	bool havensec3;
	/* NSEC3 parameters */
	dns_hash_t hash;
	uint8_t flags;
	uint16_t iterations;
	uint8_t salt_length;
	unsigned char salt[DNS_NSEC3_SALTSIZE];

	/*
	 * records and xfrsize are covered by rwlock.
	 */
	isc_rwlock_t rwlock;
	uint64_t records;
	uint64_t xfrsize;

	isc_rwlock_t glue_rwlock;
	size_t glue_table_bits;
	size_t glue_table_nodecount;
	rbtdb_glue_table_node_t **glue_table;
} rbtdb_version_t;

typedef ISC_LIST(rbtdb_version_t) rbtdb_versionlist_t;

struct dns_rbtdb {
	/* Unlocked. */
	dns_db_t common;
	/* Locks the data in this struct */
	isc_rwlock_t lock;
	/* Locks the tree structure (prevents nodes appearing/disappearing) */
	isc_rwlock_t tree_lock;
	/* Locks for individual tree nodes */
	unsigned int node_lock_count;
	rbtdb_nodelock_t *node_locks;
	dns_rbtnode_t *origin_node;
	dns_rbtnode_t *nsec3_origin_node;
	dns_stats_t *rrsetstats; /* cache DB only */
	isc_stats_t *cachestats; /* cache DB only */
	/* Locked by lock. */
	unsigned int active;
	isc_refcount_t references;
	unsigned int attributes;
	rbtdb_serial_t current_serial;
	rbtdb_serial_t least_serial;
	rbtdb_serial_t next_serial;
	rbtdb_version_t *current_version;
	rbtdb_version_t *future_version;
	rbtdb_versionlist_t open_versions;
	isc_task_t *task;
	dns_dbnode_t *soanode;
	dns_dbnode_t *nsnode;

	/*
	 * Maximum length of time to keep using a stale answer past its
	 * normal TTL expiry.
	 */
	dns_ttl_t serve_stale_ttl;

	/*
	 * The time after a failed lookup, where stale answers from cache
	 * may be used directly in a DNS response without attempting a
	 * new iterative lookup.
	 */
	uint32_t serve_stale_refresh;

	/*
	 * This is a linked list used to implement the LRU cache.  There will
	 * be node_lock_count linked lists here.  Nodes in bucket 1 will be
	 * placed on the linked list rdatasets[1].
	 */
	rdatasetheaderlist_t *rdatasets;

	/*%
	 * Temporary storage for stale cache nodes and dynamically deleted
	 * nodes that await being cleaned up.
	 */
	rbtnodelist_t *deadnodes;

	/*
	 * Heaps.  These are used for TTL based expiry in a cache,
	 * or for zone resigning in a zone DB.  hmctx is the memory
	 * context to use for the heap (which differs from the main
	 * database memory context in the case of a cache).
	 */
	isc_mem_t *hmctx;
	isc_heap_t **heaps;

	/* Locked by tree_lock. */
	dns_rbt_t *tree;
	dns_rbt_t *nsec;
	dns_rbt_t *nsec3;

	/* Unlocked */
	unsigned int quantum;
};

#define RBTDB_ATTR_LOADED  0x01
#define RBTDB_ATTR_LOADING 0x02

#define KEEPSTALE(rbtdb) ((rbtdb)->serve_stale_ttl > 0)

/*%
 * Search Context
 */
typedef struct {
	dns_rbtdb_t *rbtdb;
	rbtdb_version_t *rbtversion;
	rbtdb_serial_t serial;
	unsigned int options;
	dns_rbtnodechain_t chain;
	bool copy_name;
	bool need_cleanup;
	bool wild;
	dns_rbtnode_t *zonecut;
	rdatasetheader_t *zonecut_rdataset;
	rdatasetheader_t *zonecut_sigrdataset;
	dns_fixedname_t zonecut_name;
	isc_stdtime_t now;
} rbtdb_search_t;

/*%
 * Load Context
 */
typedef struct {
	dns_rbtdb_t *rbtdb;
	isc_stdtime_t now;
} rbtdb_load_t;

static void
delete_callback(void *data, void *arg);
static void
rdataset_disassociate(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_first(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_next(dns_rdataset_t *rdataset);
static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target);
static unsigned int
rdataset_count(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *neg, dns_rdataset_t *negsig);
static isc_result_t
rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *neg, dns_rdataset_t *negsig);
static inline bool
need_headerupdate(rdatasetheader_t *header, isc_stdtime_t now);
static void
update_header(dns_rbtdb_t *rbtdb, rdatasetheader_t *header, isc_stdtime_t now);
static void
expire_header(dns_rbtdb_t *rbtdb, rdatasetheader_t *header, bool tree_locked,
	      expire_t reason);
static void
overmem_purge(dns_rbtdb_t *rbtdb, unsigned int locknum_start, isc_stdtime_t now,
	      bool tree_locked);
static isc_result_t
resign_insert(dns_rbtdb_t *rbtdb, int idx, rdatasetheader_t *newheader);
static void
resign_delete(dns_rbtdb_t *rbtdb, rbtdb_version_t *version,
	      rdatasetheader_t *header);
static void
prune_tree(isc_task_t *task, isc_event_t *event);
static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust);
static void
rdataset_expire(dns_rdataset_t *rdataset);
static void
rdataset_clearprefetch(dns_rdataset_t *rdataset);
static void
rdataset_setownercase(dns_rdataset_t *rdataset, const dns_name_t *name);
static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name);
static isc_result_t
rdataset_addglue(dns_rdataset_t *rdataset, dns_dbversion_t *version,
		 dns_message_t *msg);
static void
free_gluetable(rbtdb_version_t *version);
static isc_result_t
nodefullname(dns_db_t *db, dns_dbnode_t *node, dns_name_t *name);

static dns_rdatasetmethods_t rdataset_methods = { rdataset_disassociate,
						  rdataset_first,
						  rdataset_next,
						  rdataset_current,
						  rdataset_clone,
						  rdataset_count,
						  NULL, /* addnoqname */
						  rdataset_getnoqname,
						  NULL, /* addclosest */
						  rdataset_getclosest,
						  rdataset_settrust,
						  rdataset_expire,
						  rdataset_clearprefetch,
						  rdataset_setownercase,
						  rdataset_getownercase,
						  rdataset_addglue };

static dns_rdatasetmethods_t slab_methods = {
	rdataset_disassociate,
	rdataset_first,
	rdataset_next,
	rdataset_current,
	rdataset_clone,
	rdataset_count,
	NULL, /* addnoqname */
	NULL, /* getnoqname */
	NULL, /* addclosest */
	NULL, /* getclosest */
	NULL, /* settrust */
	NULL, /* expire */
	NULL, /* clearprefetch */
	NULL, /* setownercase */
	NULL, /* getownercase */
	NULL  /* addglue */
};

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp);
static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator);
static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator);
static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy, rdatasetiter_first, rdatasetiter_next,
	rdatasetiter_current
};

typedef struct rbtdb_rdatasetiter {
	dns_rdatasetiter_t common;
	rdatasetheader_t *current;
} rbtdb_rdatasetiter_t;

/*
 * Note that these iterators, unless created with either DNS_DB_NSEC3ONLY or
 * DNS_DB_NONSEC3, will transparently move between the last node of the
 * "regular" RBT ("chain" field) and the root node of the NSEC3 RBT
 * ("nsec3chain" field) of the database in question, as if the latter was a
 * successor to the former in lexical order.  The "current" field always holds
 * the address of either "chain" or "nsec3chain", depending on which RBT is
 * being traversed at given time.
 */
static void
dbiterator_destroy(dns_dbiterator_t **iteratorp);
static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator, const dns_name_t *name);
static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name);
static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name);

static dns_dbiteratormethods_t dbiterator_methods = {
	dbiterator_destroy, dbiterator_first, dbiterator_last,
	dbiterator_seek,    dbiterator_prev,  dbiterator_next,
	dbiterator_current, dbiterator_pause, dbiterator_origin
};

#define DELETION_BATCH_MAX 64

/*
 * If 'paused' is true, then the tree lock is not being held.
 */
typedef struct rbtdb_dbiterator {
	dns_dbiterator_t common;
	bool paused;
	bool new_origin;
	isc_rwlocktype_t tree_locked;
	isc_result_t result;
	dns_fixedname_t name;
	dns_fixedname_t origin;
	dns_rbtnodechain_t chain;
	dns_rbtnodechain_t nsec3chain;
	dns_rbtnodechain_t *current;
	dns_rbtnode_t *node;
	dns_rbtnode_t *deletions[DELETION_BATCH_MAX];
	int delcnt;
	bool nsec3only;
	bool nonsec3;
} rbtdb_dbiterator_t;

static void
free_rbtdb(dns_rbtdb_t *rbtdb, bool log, isc_event_t *event);
static void
overmem(dns_db_t *db, bool over);
static void
setnsec3parameters(dns_db_t *db, rbtdb_version_t *version);
static void
setownercase(rdatasetheader_t *header, const dns_name_t *name);

/*%
 * 'init_count' is used to initialize 'newheader->count' which inturn
 * is used to determine where in the cycle rrset-order cyclic starts.
 * We don't lock this as we don't care about simultaneous updates.
 *
 * Note:
 *      Both init_count and header->count can be UINT32_MAX.
 *      The count on the returned rdataset however can't be as
 *      that indicates that the database does not implement cyclic
 *      processing.
 */
static atomic_uint_fast32_t init_count = ATOMIC_VAR_INIT(0);

/*
 * Locking
 *
 * If a routine is going to lock more than one lock in this module, then
 * the locking must be done in the following order:
 *
 *      Tree Lock
 *
 *      Node Lock       (Only one from the set may be locked at one time by
 *                       any caller)
 *
 *      Database Lock
 *
 * Failure to follow this hierarchy can result in deadlock.
 */

/*
 * Deleting Nodes
 *
 * For zone databases the node for the origin of the zone MUST NOT be deleted.
 */

/* Fixed RRSet helper macros */

#define DNS_RDATASET_LENGTH 2;

#if DNS_RDATASET_FIXED
#define DNS_RDATASET_ORDER 2
#define DNS_RDATASET_COUNT (count * 4)
#else /* !DNS_RDATASET_FIXED */
#define DNS_RDATASET_ORDER 0
#define DNS_RDATASET_COUNT 0
#endif /* DNS_RDATASET_FIXED */

/*
 * DB Routines
 */

static void
attach(dns_db_t *source, dns_db_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)source;

	REQUIRE(VALID_RBTDB(rbtdb));

	isc_refcount_increment(&rbtdb->references);

	*targetp = source;
}

static void
free_rbtdb_callback(isc_task_t *task, isc_event_t *event) {
	dns_rbtdb_t *rbtdb = event->ev_arg;

	UNUSED(task);

	free_rbtdb(rbtdb, true, event);
}

static void
update_cachestats(dns_rbtdb_t *rbtdb, isc_result_t result) {
	if (rbtdb->cachestats == NULL) {
		return;
	}

	switch (result) {
	case ISC_R_SUCCESS:
	case DNS_R_CNAME:
	case DNS_R_DNAME:
	case DNS_R_DELEGATION:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NCACHENXRRSET:
		isc_stats_increment(rbtdb->cachestats,
				    dns_cachestatscounter_hits);
		break;
	default:
		isc_stats_increment(rbtdb->cachestats,
				    dns_cachestatscounter_misses);
	}
}

static bool
do_stats(rdatasetheader_t *header) {
	return (EXISTS(header) && STATCOUNT(header));
}

static void
update_rrsetstats(dns_rbtdb_t *rbtdb, const rbtdb_rdatatype_t htype,
		  const uint_least16_t hattributes, const bool increment) {
	dns_rdatastatstype_t statattributes = 0;
	dns_rdatastatstype_t base = 0;
	dns_rdatastatstype_t type;
	rdatasetheader_t *header = &(rdatasetheader_t){
		.type = htype, .attributes = ATOMIC_VAR_INIT(hattributes)
	};

	if (!do_stats(header)) {
		return;
	}

	if (NEGATIVE(header)) {
		if (NXDOMAIN(header)) {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXDOMAIN;
		} else {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXRRSET;
			base = RBTDB_RDATATYPE_EXT(header->type);
		}
	} else {
		base = RBTDB_RDATATYPE_BASE(header->type);
	}

	if (STALE(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_STALE;
	}
	if (ANCIENT(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_ANCIENT;
	}

	type = DNS_RDATASTATSTYPE_VALUE(base, statattributes);
	if (increment) {
		dns_rdatasetstats_increment(rbtdb->rrsetstats, type);
	} else {
		dns_rdatasetstats_decrement(rbtdb->rrsetstats, type);
	}
}

static void
set_ttl(dns_rbtdb_t *rbtdb, rdatasetheader_t *header, dns_ttl_t newttl) {
	int idx;
	isc_heap_t *heap;
	dns_ttl_t oldttl = header->rdh_ttl;

	header->rdh_ttl = newttl;

	/*
	 * It's possible the rbtdb is not a cache.  If this is the case,
	 * we will not have a heap, and we move on.  If we do, though,
	 * we might need to adjust things.
	 */
	if (header->heap_index == 0 || newttl == oldttl) {
		return;
	}
	idx = header->node->locknum;
	if (rbtdb->heaps == NULL || rbtdb->heaps[idx] == NULL) {
		return;
	}
	heap = rbtdb->heaps[idx];

	if (newttl < oldttl) {
		isc_heap_increased(heap, header->heap_index);
	} else {
		isc_heap_decreased(heap, header->heap_index);
	}
}

/*%
 * These functions allow the heap code to rank the priority of each
 * element.  It returns true if v1 happens "sooner" than v2.
 */
static bool
ttl_sooner(void *v1, void *v2) {
	rdatasetheader_t *h1 = v1;
	rdatasetheader_t *h2 = v2;

	return (h1->rdh_ttl < h2->rdh_ttl);
}

/*%
 * This function sets the heap index into the header.
 */
static void
set_index(void *what, unsigned int idx) {
	rdatasetheader_t *h = what;

	h->heap_index = idx;
}

/*%
 * Work out how many nodes can be deleted in the time between two
 * requests to the nameserver.  Smooth the resulting number and use it
 * as a estimate for the number of nodes to be deleted in the next
 * iteration.
 */
static unsigned int
adjust_quantum(unsigned int old, isc_time_t *start) {
	unsigned int pps = dns_pps; /* packets per second */
	unsigned int interval;
	uint64_t usecs;
	isc_time_t end;
	unsigned int nodes;

	if (pps < 100) {
		pps = 100;
	}
	isc_time_now(&end);

	interval = 1000000 / pps; /* interval in usec */
	if (interval == 0) {
		interval = 1;
	}
	usecs = isc_time_microdiff(&end, start);
	if (usecs == 0) {
		/*
		 * We were unable to measure the amount of time taken.
		 * Double the nodes deleted next time.
		 */
		old *= 2;
		if (old > 1000) {
			old = 1000;
		}
		return (old);
	}
	nodes = old * interval;
	nodes /= (unsigned int)usecs;
	if (nodes == 0) {
		nodes = 1;
	} else if (nodes > 1000) {
		nodes = 1000;
	}

	/* Smooth */
	nodes = (nodes + old * 3) / 4;

	if (nodes != old) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "adjust_quantum: old=%d, new=%d", old, nodes);
	}

	return (nodes);
}

static void
free_rbtdb(dns_rbtdb_t *rbtdb, bool log, isc_event_t *event) {
	unsigned int i;
	isc_result_t result;
	char buf[DNS_NAME_FORMATSIZE];
	dns_rbt_t **treep;
	isc_time_t start;
	dns_dbonupdatelistener_t *listener, *listener_next;

	if (rbtdb->common.rdclass == dns_rdataclass_in) {
		overmem((dns_db_t *)rbtdb, (bool)-1);
	}

	REQUIRE(rbtdb->current_version != NULL || EMPTY(rbtdb->open_versions));
	REQUIRE(rbtdb->future_version == NULL);

	if (rbtdb->current_version != NULL) {
		isc_refcount_decrementz(&rbtdb->current_version->references);
		UNLINK(rbtdb->open_versions, rbtdb->current_version, link);
		isc_rwlock_destroy(&rbtdb->current_version->glue_rwlock);
		isc_refcount_destroy(&rbtdb->current_version->references);
		isc_rwlock_destroy(&rbtdb->current_version->rwlock);
		isc_mem_put(rbtdb->common.mctx, rbtdb->current_version,
			    sizeof(rbtdb_version_t));
	}

	/*
	 * We assume the number of remaining dead nodes is reasonably small;
	 * the overhead of unlinking all nodes here should be negligible.
	 */
	for (i = 0; i < rbtdb->node_lock_count; i++) {
		dns_rbtnode_t *node;

		node = ISC_LIST_HEAD(rbtdb->deadnodes[i]);
		while (node != NULL) {
			ISC_LIST_UNLINK(rbtdb->deadnodes[i], node, deadlink);
			node = ISC_LIST_HEAD(rbtdb->deadnodes[i]);
		}
	}

	if (event == NULL) {
		rbtdb->quantum = (rbtdb->task != NULL) ? 100 : 0;
	}

	for (;;) {
		/*
		 * pick the next tree to (start to) destroy
		 */
		treep = &rbtdb->tree;
		if (*treep == NULL) {
			treep = &rbtdb->nsec;
			if (*treep == NULL) {
				treep = &rbtdb->nsec3;
				/*
				 * we're finished after clear cutting
				 */
				if (*treep == NULL) {
					break;
				}
			}
		}

		isc_time_now(&start);
		result = dns_rbt_destroy2(treep, rbtdb->quantum);
		if (result == ISC_R_QUOTA) {
			INSIST(rbtdb->task != NULL);
			if (rbtdb->quantum != 0) {
				rbtdb->quantum = adjust_quantum(rbtdb->quantum,
								&start);
			}
			if (event == NULL) {
				event = isc_event_allocate(
					rbtdb->common.mctx, NULL,
					DNS_EVENT_FREESTORAGE,
					free_rbtdb_callback, rbtdb,
					sizeof(isc_event_t));
			}
			isc_task_send(rbtdb->task, &event);
			return;
		}
		INSIST(result == ISC_R_SUCCESS && *treep == NULL);
	}

	if (event != NULL) {
		isc_event_free(&event);
	}
	if (log) {
		if (dns_name_dynamic(&rbtdb->common.origin)) {
			dns_name_format(&rbtdb->common.origin, buf,
					sizeof(buf));
		} else {
			strlcpy(buf, "<UNKNOWN>", sizeof(buf));
		}
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "done free_rbtdb(%s)", buf);
	}
	if (dns_name_dynamic(&rbtdb->common.origin)) {
		dns_name_free(&rbtdb->common.origin, rbtdb->common.mctx);
	}
	for (i = 0; i < rbtdb->node_lock_count; i++) {
		isc_refcount_destroy(&rbtdb->node_locks[i].references);
		NODE_DESTROYLOCK(&rbtdb->node_locks[i].lock);
	}

	/*
	 * Clean up LRU / re-signing order lists.
	 */
	if (rbtdb->rdatasets != NULL) {
		for (i = 0; i < rbtdb->node_lock_count; i++) {
			INSIST(ISC_LIST_EMPTY(rbtdb->rdatasets[i]));
		}
		isc_mem_put(rbtdb->common.mctx, rbtdb->rdatasets,
			    rbtdb->node_lock_count *
				    sizeof(rdatasetheaderlist_t));
	}
	/*
	 * Clean up dead node buckets.
	 */
	if (rbtdb->deadnodes != NULL) {
		for (i = 0; i < rbtdb->node_lock_count; i++) {
			INSIST(ISC_LIST_EMPTY(rbtdb->deadnodes[i]));
		}
		isc_mem_put(rbtdb->common.mctx, rbtdb->deadnodes,
			    rbtdb->node_lock_count * sizeof(rbtnodelist_t));
	}
	/*
	 * Clean up heap objects.
	 */
	if (rbtdb->heaps != NULL) {
		for (i = 0; i < rbtdb->node_lock_count; i++) {
			isc_heap_destroy(&rbtdb->heaps[i]);
		}
		isc_mem_put(rbtdb->hmctx, rbtdb->heaps,
			    rbtdb->node_lock_count * sizeof(isc_heap_t *));
	}

	if (rbtdb->rrsetstats != NULL) {
		dns_stats_detach(&rbtdb->rrsetstats);
	}
	if (rbtdb->cachestats != NULL) {
		isc_stats_detach(&rbtdb->cachestats);
	}

	isc_mem_put(rbtdb->common.mctx, rbtdb->node_locks,
		    rbtdb->node_lock_count * sizeof(rbtdb_nodelock_t));
	isc_rwlock_destroy(&rbtdb->tree_lock);
	isc_refcount_destroy(&rbtdb->references);
	if (rbtdb->task != NULL) {
		isc_task_detach(&rbtdb->task);
	}

	RBTDB_DESTROYLOCK(&rbtdb->lock);
	rbtdb->common.magic = 0;
	rbtdb->common.impmagic = 0;
	isc_mem_detach(&rbtdb->hmctx);

	for (listener = ISC_LIST_HEAD(rbtdb->common.update_listeners);
	     listener != NULL; listener = listener_next)
	{
		listener_next = ISC_LIST_NEXT(listener, link);
		ISC_LIST_UNLINK(rbtdb->common.update_listeners, listener, link);
		isc_mem_put(rbtdb->common.mctx, listener,
			    sizeof(dns_dbonupdatelistener_t));
	}

	isc_mem_putanddetach(&rbtdb->common.mctx, rbtdb, sizeof(*rbtdb));
}

static inline void
maybe_free_rbtdb(dns_rbtdb_t *rbtdb) {
	bool want_free = false;
	unsigned int i;
	unsigned int inactive = 0;

	/* XXX check for open versions here */

	if (rbtdb->soanode != NULL) {
		dns_db_detachnode((dns_db_t *)rbtdb, &rbtdb->soanode);
	}
	if (rbtdb->nsnode != NULL) {
		dns_db_detachnode((dns_db_t *)rbtdb, &rbtdb->nsnode);
	}

	/*
	 * The current version's glue table needs to be freed early
	 * so the nodes are dereferenced before we check the active
	 * node count below.
	 */
	if (rbtdb->current_version != NULL) {
		free_gluetable(rbtdb->current_version);
	}

	/*
	 * Even though there are no external direct references, there still
	 * may be nodes in use.
	 */
	for (i = 0; i < rbtdb->node_lock_count; i++) {
		NODE_LOCK(&rbtdb->node_locks[i].lock, isc_rwlocktype_write);
		rbtdb->node_locks[i].exiting = true;
		if (isc_refcount_current(&rbtdb->node_locks[i].references) == 0)
		{
			inactive++;
		}
		NODE_UNLOCK(&rbtdb->node_locks[i].lock, isc_rwlocktype_write);
	}

	if (inactive != 0) {
		RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);
		rbtdb->active -= inactive;
		if (rbtdb->active == 0) {
			want_free = true;
		}
		RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);
		if (want_free) {
			char buf[DNS_NAME_FORMATSIZE];
			if (dns_name_dynamic(&rbtdb->common.origin)) {
				dns_name_format(&rbtdb->common.origin, buf,
						sizeof(buf));
			} else {
				strlcpy(buf, "<UNKNOWN>", sizeof(buf));
			}
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
				      "calling free_rbtdb(%s)", buf);
			free_rbtdb(rbtdb, true, NULL);
		}
	}
}

static void
detach(dns_db_t **dbp) {
	REQUIRE(dbp != NULL && VALID_RBTDB((dns_rbtdb_t *)(*dbp)));
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(*dbp);
	*dbp = NULL;

	if (isc_refcount_decrement(&rbtdb->references) == 1) {
		maybe_free_rbtdb(rbtdb);
	}
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *version;

	REQUIRE(VALID_RBTDB(rbtdb));

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_read);
	version = rbtdb->current_version;
	isc_refcount_increment(&version->references);
	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_read);

	*versionp = (dns_dbversion_t *)version;
}

static inline rbtdb_version_t *
allocate_version(isc_mem_t *mctx, rbtdb_serial_t serial,
		 unsigned int references, bool writer) {
	rbtdb_version_t *version;
	size_t size;

	version = isc_mem_get(mctx, sizeof(*version));
	version->serial = serial;

	isc_refcount_init(&version->references, references);
	isc_rwlock_init(&version->glue_rwlock, 0, 0);

	version->glue_table_bits = RBTDB_GLUE_TABLE_INIT_BITS;
	version->glue_table_nodecount = 0U;

	size = HASHSIZE(version->glue_table_bits) *
	       sizeof(version->glue_table[0]);
	version->glue_table = isc_mem_get(mctx, size);
	memset(version->glue_table, 0, size);

	version->writer = writer;
	version->commit_ok = false;
	ISC_LIST_INIT(version->changed_list);
	ISC_LIST_INIT(version->resigned_list);
	ISC_LINK_INIT(version, link);

	return (version);
}

static isc_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *version;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(versionp != NULL && *versionp == NULL);
	REQUIRE(rbtdb->future_version == NULL);

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);
	RUNTIME_CHECK(rbtdb->next_serial != 0); /* XXX Error? */
	version = allocate_version(rbtdb->common.mctx, rbtdb->next_serial, 1,
				   true);
	version->rbtdb = rbtdb;
	version->commit_ok = true;
	version->secure = rbtdb->current_version->secure;
	version->havensec3 = rbtdb->current_version->havensec3;
	if (version->havensec3) {
		version->flags = rbtdb->current_version->flags;
		version->iterations = rbtdb->current_version->iterations;
		version->hash = rbtdb->current_version->hash;
		version->salt_length = rbtdb->current_version->salt_length;
		memmove(version->salt, rbtdb->current_version->salt,
			version->salt_length);
	} else {
		version->flags = 0;
		version->iterations = 0;
		version->hash = 0;
		version->salt_length = 0;
		memset(version->salt, 0, sizeof(version->salt));
	}
	isc_rwlock_init(&version->rwlock, 0, 0);
	RWLOCK(&rbtdb->current_version->rwlock, isc_rwlocktype_read);
	version->records = rbtdb->current_version->records;
	version->xfrsize = rbtdb->current_version->xfrsize;
	RWUNLOCK(&rbtdb->current_version->rwlock, isc_rwlocktype_read);
	rbtdb->next_serial++;
	rbtdb->future_version = version;
	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);

	*versionp = version;

	return (ISC_R_SUCCESS);
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *rbtversion = source;

	REQUIRE(VALID_RBTDB(rbtdb));
	INSIST(rbtversion != NULL && rbtversion->rbtdb == rbtdb);

	isc_refcount_increment(&rbtversion->references);

	*targetp = rbtversion;
}

static rbtdb_changed_t *
add_changed(dns_rbtdb_t *rbtdb, rbtdb_version_t *version, dns_rbtnode_t *node) {
	rbtdb_changed_t *changed;

	/*
	 * Caller must be holding the node lock if its reference must be
	 * protected by the lock.
	 */

	changed = isc_mem_get(rbtdb->common.mctx, sizeof(*changed));

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);

	REQUIRE(version->writer);

	if (changed != NULL) {
		isc_refcount_increment(&node->references);
		changed->node = node;
		changed->dirty = false;
		ISC_LIST_INITANDAPPEND(version->changed_list, changed, link);
	} else {
		version->commit_ok = false;
	}

	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);

	return (changed);
}

static inline void
free_noqname(isc_mem_t *mctx, struct noqname **noqname) {
	if (dns_name_dynamic(&(*noqname)->name)) {
		dns_name_free(&(*noqname)->name, mctx);
	}
	if ((*noqname)->neg != NULL) {
		isc_mem_put(mctx, (*noqname)->neg,
			    dns_rdataslab_size((*noqname)->neg, 0));
	}
	if ((*noqname)->negsig != NULL) {
		isc_mem_put(mctx, (*noqname)->negsig,
			    dns_rdataslab_size((*noqname)->negsig, 0));
	}
	isc_mem_put(mctx, *noqname, sizeof(**noqname));
	*noqname = NULL;
}

static inline void
init_rdataset(dns_rbtdb_t *rbtdb, rdatasetheader_t *h) {
	ISC_LINK_INIT(h, link);
	h->heap_index = 0;
	atomic_init(&h->attributes, 0);
	atomic_init(&h->last_refresh_fail_ts, 0);

	STATIC_ASSERT((sizeof(h->attributes) == 2),
		      "The .attributes field of rdatasetheader_t needs to be "
		      "16-bit int type exactly.");

#if TRACE_HEADER
	if (rbtdb->common.rdclass == dns_rdataclass_in) {
		fprintf(stderr, "initialized header: %p\n", h);
	}
#else  /* if TRACE_HEADER */
	UNUSED(rbtdb);
#endif /* if TRACE_HEADER */
}

static void
update_newheader(rdatasetheader_t *newh, rdatasetheader_t *old) {
	if (CASESET(old)) {
		uint_least16_t attr = RDATASET_ATTR_GET(
			old,
			(RDATASET_ATTR_CASESET | RDATASET_ATTR_CASEFULLYLOWER));
		RDATASET_ATTR_SET(newh, attr);
		memmove(newh->upper, old->upper, sizeof(old->upper));
	}
}

static inline rdatasetheader_t *
new_rdataset(dns_rbtdb_t *rbtdb, isc_mem_t *mctx) {
	rdatasetheader_t *h;

	h = isc_mem_get(mctx, sizeof(*h));

#if TRACE_HEADER
	if (rbtdb->common.rdclass == dns_rdataclass_in) {
		fprintf(stderr, "allocated header: %p\n", h);
	}
#endif /* if TRACE_HEADER */
	memset(h->upper, 0xeb, sizeof(h->upper));
	init_rdataset(rbtdb, h);
	h->rdh_ttl = 0;
	return (h);
}

static inline void
free_rdataset(dns_rbtdb_t *rbtdb, isc_mem_t *mctx, rdatasetheader_t *rdataset) {
	unsigned int size;
	int idx;

	update_rrsetstats(rbtdb, rdataset->type,
			  atomic_load_acquire(&rdataset->attributes), false);

	idx = rdataset->node->locknum;
	if (ISC_LINK_LINKED(rdataset, link)) {
		ISC_LIST_UNLINK(rbtdb->rdatasets[idx], rdataset, link);
	}

	if (rdataset->heap_index != 0) {
		isc_heap_delete(rbtdb->heaps[idx], rdataset->heap_index);
	}
	rdataset->heap_index = 0;

	if (rdataset->noqname != NULL) {
		free_noqname(mctx, &rdataset->noqname);
	}
	if (rdataset->closest != NULL) {
		free_noqname(mctx, &rdataset->closest);
	}

	if (NONEXISTENT(rdataset)) {
		size = sizeof(*rdataset);
	} else {
		size = dns_rdataslab_size((unsigned char *)rdataset,
					  sizeof(*rdataset));
	}

	isc_mem_put(mctx, rdataset, size);
}

static inline void
rollback_node(dns_rbtnode_t *node, rbtdb_serial_t serial) {
	rdatasetheader_t *header, *dcurrent;
	bool make_dirty = false;

	/*
	 * Caller must hold the node lock.
	 */

	/*
	 * We set the IGNORE attribute on rdatasets with serial number
	 * 'serial'.  When the reference count goes to zero, these rdatasets
	 * will be cleaned up; until that time, they will be ignored.
	 */
	for (header = node->data; header != NULL; header = header->next) {
		if (header->serial == serial) {
			RDATASET_ATTR_SET(header, RDATASET_ATTR_IGNORE);
			make_dirty = true;
		}
		for (dcurrent = header->down; dcurrent != NULL;
		     dcurrent = dcurrent->down) {
			if (dcurrent->serial == serial) {
				RDATASET_ATTR_SET(dcurrent,
						  RDATASET_ATTR_IGNORE);
				make_dirty = true;
			}
		}
	}
	if (make_dirty) {
		node->dirty = 1;
	}
}

static inline void
mark_header_ancient(dns_rbtdb_t *rbtdb, rdatasetheader_t *header) {
	uint_least16_t attributes = atomic_load_acquire(&header->attributes);
	uint_least16_t newattributes = 0;

	/*
	 * If we are already ancient there is nothing to do.
	 */
	do {
		if ((attributes & RDATASET_ATTR_ANCIENT) != 0) {
			return;
		}
		newattributes = attributes | RDATASET_ATTR_ANCIENT;
	} while (!atomic_compare_exchange_weak_acq_rel(
		&header->attributes, &attributes, newattributes));

	/*
	 * Decrement the stats counter for the appropriate RRtype.
	 * If the STALE attribute is set, this will decrement the
	 * stale type counter, otherwise it decrements the active
	 * stats type counter.
	 */
	update_rrsetstats(rbtdb, header->type, attributes, false);
	header->node->dirty = 1;

	/* Increment the stats counter for the ancient RRtype. */
	update_rrsetstats(rbtdb, header->type, newattributes, true);
}

static inline void
mark_header_stale(dns_rbtdb_t *rbtdb, rdatasetheader_t *header) {
	uint_least16_t attributes = atomic_load_acquire(&header->attributes);
	uint_least16_t newattributes = 0;

	INSIST((attributes & RDATASET_ATTR_ZEROTTL) == 0);

	/*
	 * If we are already stale there is nothing to do.
	 */
	do {
		if ((attributes & RDATASET_ATTR_STALE) != 0) {
			return;
		}
		newattributes = attributes | RDATASET_ATTR_STALE;
	} while (!atomic_compare_exchange_weak_acq_rel(
		&header->attributes, &attributes, newattributes));

	/* Decrement the stats counter for the appropriate RRtype.
	 * If the ANCIENT attribute is set (although it is very
	 * unlikely that an RRset goes from ANCIENT to STALE), this
	 * will decrement the ancient stale type counter, otherwise it
	 * decrements the active stats type counter.
	 */

	update_rrsetstats(rbtdb, header->type, attributes, false);
	update_rrsetstats(rbtdb, header->type, newattributes, true);
}

static inline void
clean_stale_headers(dns_rbtdb_t *rbtdb, isc_mem_t *mctx,
		    rdatasetheader_t *top) {
	rdatasetheader_t *d, *down_next;

	for (d = top->down; d != NULL; d = down_next) {
		down_next = d->down;
		free_rdataset(rbtdb, mctx, d);
	}
	top->down = NULL;
}

static inline void
clean_cache_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node) {
	rdatasetheader_t *current, *top_prev, *top_next;
	isc_mem_t *mctx = rbtdb->common.mctx;

	/*
	 * Caller must be holding the node lock.
	 */

	top_prev = NULL;
	for (current = node->data; current != NULL; current = top_next) {
		top_next = current->next;
		clean_stale_headers(rbtdb, mctx, current);
		/*
		 * If current is nonexistent, ancient, or stale and
		 * we are not keeping stale, we can clean it up.
		 */
		if (NONEXISTENT(current) || ANCIENT(current) ||
		    (STALE(current) && !KEEPSTALE(rbtdb)))
		{
			if (top_prev != NULL) {
				top_prev->next = current->next;
			} else {
				node->data = current->next;
			}
			free_rdataset(rbtdb, mctx, current);
		} else {
			top_prev = current;
		}
	}
	node->dirty = 0;
}

/*
 * tree_lock(write) must be held.
 */
static void
delete_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node) {
	dns_rbtnode_t *nsecnode;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_result_t result = ISC_R_UNEXPECTED;

	INSIST(!ISC_LINK_LINKED(node, deadlink));

	if (isc_log_wouldlog(dns_lctx, ISC_LOG_DEBUG(1))) {
		char printname[DNS_NAME_FORMATSIZE];
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "delete_node(): %p %s (bucket %d)", node,
			      dns_rbt_formatnodename(node, printname,
						     sizeof(printname)),
			      node->locknum);
	}

	switch (node->nsec) {
	case DNS_RBT_NSEC_NORMAL:
		/*
		 * Though this may be wasteful, it has to be done before
		 * node is deleted.
		 */
		name = dns_fixedname_initname(&fname);
		dns_rbt_fullnamefromnode(node, name);

		result = dns_rbt_deletenode(rbtdb->tree, node, false);
		break;
	case DNS_RBT_NSEC_HAS_NSEC:
		name = dns_fixedname_initname(&fname);
		dns_rbt_fullnamefromnode(node, name);
		/*
		 * Delete the corresponding node from the auxiliary NSEC
		 * tree before deleting from the main tree.
		 */
		nsecnode = NULL;
		result = dns_rbt_findnode(rbtdb->nsec, name, NULL, &nsecnode,
					  NULL, DNS_RBTFIND_EMPTYDATA, NULL,
					  NULL);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
				      "delete_node: "
				      "dns_rbt_findnode(nsec): %s",
				      isc_result_totext(result));
		} else {
			result = dns_rbt_deletenode(rbtdb->nsec, nsecnode,
						    false);
			if (result != ISC_R_SUCCESS) {
				isc_log_write(
					dns_lctx, DNS_LOGCATEGORY_DATABASE,
					DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
					"delete_node(): "
					"dns_rbt_deletenode(nsecnode): %s",
					isc_result_totext(result));
			}
		}
		result = dns_rbt_deletenode(rbtdb->tree, node, false);
		break;
	case DNS_RBT_NSEC_NSEC:
		result = dns_rbt_deletenode(rbtdb->nsec, node, false);
		break;
	case DNS_RBT_NSEC_NSEC3:
		result = dns_rbt_deletenode(rbtdb->nsec3, node, false);
		break;
	}
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
			      "delete_node(): "
			      "dns_rbt_deletenode: %s",
			      isc_result_totext(result));
	}
}

/*
 * Caller must be holding the node lock.
 */
static inline void
new_reference(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
	      isc_rwlocktype_t locktype) {
	if (locktype == isc_rwlocktype_write && ISC_LINK_LINKED(node, deadlink))
	{
		ISC_LIST_UNLINK(rbtdb->deadnodes[node->locknum], node,
				deadlink);
	}
	if (isc_refcount_increment0(&node->references) == 0) {
		/* this is the first reference to the node */
		isc_refcount_increment0(
			&rbtdb->node_locks[node->locknum].references);
	}
}

/*%
 * The tree lock must be held for the result to be valid.
 */
static inline bool
is_leaf(dns_rbtnode_t *node) {
	return (node->parent != NULL && node->parent->down == node &&
		node->left == NULL && node->right == NULL);
}

static inline void
send_to_prune_tree(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
		   isc_rwlocktype_t locktype) {
	isc_event_t *ev;
	dns_db_t *db;

	ev = isc_event_allocate(rbtdb->common.mctx, NULL, DNS_EVENT_RBTPRUNE,
				prune_tree, node, sizeof(isc_event_t));
	new_reference(rbtdb, node, locktype);
	db = NULL;
	attach((dns_db_t *)rbtdb, &db);
	ev->ev_sender = db;
	isc_task_send(rbtdb->task, &ev);
}

/*%
 * Clean up dead nodes.  These are nodes which have no references, and
 * have no data.  They are dead but we could not or chose not to delete
 * them when we deleted all the data at that node because we did not want
 * to wait for the tree write lock.
 *
 * The caller must hold a tree write lock and bucketnum'th node (write) lock.
 */
static void
cleanup_dead_nodes(dns_rbtdb_t *rbtdb, int bucketnum) {
	dns_rbtnode_t *node;
	int count = 10; /* XXXJT: should be adjustable */

	node = ISC_LIST_HEAD(rbtdb->deadnodes[bucketnum]);
	while (node != NULL && count > 0) {
		ISC_LIST_UNLINK(rbtdb->deadnodes[bucketnum], node, deadlink);

		/*
		 * We might have reactivated this node without a tree write
		 * lock, so we couldn't remove this node from deadnodes then
		 * and we have to do it now.
		 */
		if (isc_refcount_current(&node->references) != 0 ||
		    node->data != NULL) {
			node = ISC_LIST_HEAD(rbtdb->deadnodes[bucketnum]);
			count--;
			continue;
		}

		if (is_leaf(node) && rbtdb->task != NULL) {
			send_to_prune_tree(rbtdb, node, isc_rwlocktype_write);
		} else if (node->down == NULL && node->data == NULL) {
			/*
			 * Not a interior node and not needing to be
			 * reactivated.
			 */
			delete_node(rbtdb, node);
		} else if (node->data == NULL) {
			/*
			 * A interior node without data. Leave linked to
			 * to be cleaned up when node->down becomes NULL.
			 */
			ISC_LIST_APPEND(rbtdb->deadnodes[bucketnum], node,
					deadlink);
		}
		node = ISC_LIST_HEAD(rbtdb->deadnodes[bucketnum]);
		count--;
	}
}

/*
 * This function is assumed to be called when a node is newly referenced
 * and can be in the deadnode list.  In that case the node must be retrieved
 * from the list because it is going to be used.  In addition, if the caller
 * happens to hold a write lock on the tree, it's a good chance to purge dead
 * nodes.
 * Note: while a new reference is gained in multiple places, there are only very
 * few cases where the node can be in the deadnode list (only empty nodes can
 * have been added to the list).
 */
static inline void
reactivate_node(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
		isc_rwlocktype_t treelocktype) {
	isc_rwlocktype_t locktype = isc_rwlocktype_read;
	nodelock_t *nodelock = &rbtdb->node_locks[node->locknum].lock;
	bool maybe_cleanup = false;

	POST(locktype);

	NODE_LOCK(nodelock, locktype);

	/*
	 * Check if we can possibly cleanup the dead node.  If so, upgrade
	 * the node lock below to perform the cleanup.
	 */
	if (!ISC_LIST_EMPTY(rbtdb->deadnodes[node->locknum]) &&
	    treelocktype == isc_rwlocktype_write)
	{
		maybe_cleanup = true;
	}

	if (ISC_LINK_LINKED(node, deadlink) || maybe_cleanup) {
		/*
		 * Upgrade the lock and test if we still need to unlink.
		 */
		NODE_UNLOCK(nodelock, locktype);
		locktype = isc_rwlocktype_write;
		POST(locktype);
		NODE_LOCK(nodelock, locktype);
		if (ISC_LINK_LINKED(node, deadlink)) {
			ISC_LIST_UNLINK(rbtdb->deadnodes[node->locknum], node,
					deadlink);
		}
		if (maybe_cleanup) {
			cleanup_dead_nodes(rbtdb, node->locknum);
		}
	}

	new_reference(rbtdb, node, locktype);

	NODE_UNLOCK(nodelock, locktype);
}

/*
 * Caller must be holding the node lock; either the "strong", read or write
 * lock.  Note that the lock must be held even when node references are
 * atomically modified; in that case the decrement operation itself does not
 * have to be protected, but we must avoid a race condition where multiple
 * threads are decreasing the reference to zero simultaneously and at least
 * one of them is going to free the node.
 *
 * This function returns true if and only if the node reference decreases
 * to zero.
 *
 * NOTE: Decrementing the reference count of a node to zero does not mean it
 * will be immediately freed.
 */
static bool
decrement_reference(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node,
		    isc_rwlocktype_t nlock, isc_rwlocktype_t tlock,
		    bool pruning) {
	isc_result_t result;
	bool write_locked;
	bool locked = tlock != isc_rwlocktype_none;
	rbtdb_nodelock_t *nodelock;
	int bucket = node->locknum;
	bool no_reference = true;
	uint_fast32_t refs;

	nodelock = &rbtdb->node_locks[bucket];

#define KEEP_NODE(n, r, l)                                  \
	((n)->data != NULL || ((l) && (n)->down != NULL) || \
	 (n) == (r)->origin_node || (n) == (r)->nsec3_origin_node)

	/* Handle easy and typical case first. */
	if (!node->dirty && KEEP_NODE(node, rbtdb, locked)) {
		if (isc_refcount_decrement(&node->references) == 1) {
			refs = isc_refcount_decrement(&nodelock->references);
			INSIST(refs > 0);
			return (true);
		} else {
			return (false);
		}
	}

	/* Upgrade the lock? */
	if (nlock == isc_rwlocktype_read) {
		NODE_UNLOCK(&nodelock->lock, isc_rwlocktype_read);
		NODE_LOCK(&nodelock->lock, isc_rwlocktype_write);
	}

	if (isc_refcount_decrement(&node->references) > 1) {
		/* Restore the lock? */
		if (nlock == isc_rwlocktype_read) {
			NODE_DOWNGRADE(&nodelock->lock);
		}
		return (false);
	}

	if (node->dirty) {
		clean_cache_node(rbtdb, node);
	}

	/*
	 * Attempt to switch to a write lock on the tree.  If this fails,
	 * we will add this node to a linked list of nodes in this locking
	 * bucket which we will free later.
	 */
	if (tlock != isc_rwlocktype_write) {
		/*
		 * Locking hierarchy notwithstanding, we don't need to free
		 * the node lock before acquiring the tree write lock because
		 * we only do a trylock.
		 */
		if (tlock == isc_rwlocktype_read) {
			result = isc_rwlock_tryupgrade(&rbtdb->tree_lock);
		} else {
			result = isc_rwlock_trylock(&rbtdb->tree_lock,
						    isc_rwlocktype_write);
		}
		RUNTIME_CHECK(result == ISC_R_SUCCESS ||
			      result == ISC_R_LOCKBUSY);

		write_locked = (result == ISC_R_SUCCESS);
	} else {
		write_locked = true;
	}

	refs = isc_refcount_decrement(&nodelock->references);
	INSIST(refs > 0);

	if (KEEP_NODE(node, rbtdb, locked || write_locked)) {
		goto restore_locks;
	}

#undef KEEP_NODE

	if (write_locked) {
		/*
		 * We can now delete the node.
		 */

		/*
		 * If this node is the only one in the level it's in, deleting
		 * this node may recursively make its parent the only node in
		 * the parent level; if so, and if no one is currently using
		 * the parent node, this is almost the only opportunity to
		 * clean it up.  But the recursive cleanup is not that trivial
		 * since the child and parent may be in different lock buckets,
		 * which would cause a lock order reversal problem.  To avoid
		 * the trouble, we'll dispatch a separate event for batch
		 * cleaning.  We need to check whether we're deleting the node
		 * as a result of pruning to avoid infinite dispatching.
		 * Note: pruning happens only when a task has been set for the
		 * rbtdb.  If the user of the rbtdb chooses not to set a task,
		 * it's their responsibility to purge stale leaves (e.g. by
		 * periodic walk-through).
		 */
		if (!pruning && is_leaf(node) && rbtdb->task != NULL) {
			send_to_prune_tree(rbtdb, node, isc_rwlocktype_write);
			no_reference = false;
		} else {
			delete_node(rbtdb, node);
		}
	} else {
		INSIST(node->data == NULL);
		if (!ISC_LINK_LINKED(node, deadlink)) {
			ISC_LIST_APPEND(rbtdb->deadnodes[bucket], node,
					deadlink);
		}
	}

restore_locks:
	/* Restore the lock? */
	if (nlock == isc_rwlocktype_read) {
		NODE_DOWNGRADE(&nodelock->lock);
	}

	/*
	 * Relock a read lock, or unlock the write lock if no lock was held.
	 */
	if (tlock == isc_rwlocktype_none) {
		if (write_locked) {
			RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
		}
	}

	if (tlock == isc_rwlocktype_read) {
		if (write_locked) {
			isc_rwlock_downgrade(&rbtdb->tree_lock);
		}
	}

	return (no_reference);
}

/*
 * Prune the tree by recursively cleaning-up single leaves.  In the worst
 * case, the number of iteration is the number of tree levels, which is at
 * most the maximum number of domain name labels, i.e, 127.  In practice, this
 * should be much smaller (only a few times), and even the worst case would be
 * acceptable for a single event.
 */
static void
prune_tree(isc_task_t *task, isc_event_t *event) {
	dns_rbtdb_t *rbtdb = event->ev_sender;
	dns_rbtnode_t *node = event->ev_arg;
	dns_rbtnode_t *parent;
	unsigned int locknum;

	UNUSED(task);

	isc_event_free(&event);

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
	locknum = node->locknum;
	NODE_LOCK(&rbtdb->node_locks[locknum].lock, isc_rwlocktype_write);
	do {
		parent = node->parent;
		decrement_reference(rbtdb, node, isc_rwlocktype_write,
				    isc_rwlocktype_write, true);

		if (parent != NULL && parent->down == NULL) {
			/*
			 * node was the only down child of the parent and has
			 * just been removed.  We'll then need to examine the
			 * parent.  Keep the lock if possible; otherwise,
			 * release the old lock and acquire one for the parent.
			 */
			if (parent->locknum != locknum) {
				NODE_UNLOCK(&rbtdb->node_locks[locknum].lock,
					    isc_rwlocktype_write);
				locknum = parent->locknum;
				NODE_LOCK(&rbtdb->node_locks[locknum].lock,
					  isc_rwlocktype_write);
			}

			/*
			 * We need to gain a reference to the node before
			 * decrementing it in the next iteration.
			 */
			if (ISC_LINK_LINKED(parent, deadlink)) {
				ISC_LIST_UNLINK(rbtdb->deadnodes[locknum],
						parent, deadlink);
			}
			new_reference(rbtdb, parent, isc_rwlocktype_write);
		} else {
			parent = NULL;
		}

		node = parent;
	} while (node != NULL);
	NODE_UNLOCK(&rbtdb->node_locks[locknum].lock, isc_rwlocktype_write);
	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);

	detach((dns_db_t **)&rbtdb);
}

static inline void
make_least_version(dns_rbtdb_t *rbtdb, rbtdb_version_t *version,
		   rbtdb_changedlist_t *cleanup_list) {
	/*
	 * Caller must be holding the database lock.
	 */

	rbtdb->least_serial = version->serial;
	*cleanup_list = version->changed_list;
	ISC_LIST_INIT(version->changed_list);
}

static inline void
cleanup_nondirty(rbtdb_version_t *version, rbtdb_changedlist_t *cleanup_list) {
	rbtdb_changed_t *changed, *next_changed;

	/*
	 * If the changed record is dirty, then
	 * an update created multiple versions of
	 * a given rdataset.  We keep this list
	 * until we're the least open version, at
	 * which point it's safe to get rid of any
	 * older versions.
	 *
	 * If the changed record isn't dirty, then
	 * we don't need it anymore since we're
	 * committing and not rolling back.
	 *
	 * The caller must be holding the database lock.
	 */
	for (changed = HEAD(version->changed_list); changed != NULL;
	     changed = next_changed)
	{
		next_changed = NEXT(changed, link);
		if (!changed->dirty) {
			UNLINK(version->changed_list, changed, link);
			APPEND(*cleanup_list, changed, link);
		}
	}
}

static void
iszonesecure(dns_db_t *db, rbtdb_version_t *version, dns_dbnode_t *origin) {
	dns_rdataset_t keyset;
	dns_rdataset_t nsecset, signsecset;
	bool haszonekey = false;
	bool hasnsec = false;
	isc_result_t result;

	dns_rdataset_init(&keyset);
	result = dns_db_findrdataset(db, origin, version, dns_rdatatype_dnskey,
				     0, 0, &keyset, NULL);
	if (result == ISC_R_SUCCESS) {
		result = dns_rdataset_first(&keyset);
		while (result == ISC_R_SUCCESS) {
			dns_rdata_t keyrdata = DNS_RDATA_INIT;
			dns_rdataset_current(&keyset, &keyrdata);
			if (dns_zonekey_iszonekey(&keyrdata)) {
				haszonekey = true;
				break;
			}
			result = dns_rdataset_next(&keyset);
		}
		dns_rdataset_disassociate(&keyset);
	}
	if (!haszonekey) {
		version->secure = dns_db_insecure;
		version->havensec3 = false;
		return;
	}

	dns_rdataset_init(&nsecset);
	dns_rdataset_init(&signsecset);
	result = dns_db_findrdataset(db, origin, version, dns_rdatatype_nsec, 0,
				     0, &nsecset, &signsecset);
	if (result == ISC_R_SUCCESS) {
		if (dns_rdataset_isassociated(&signsecset)) {
			hasnsec = true;
			dns_rdataset_disassociate(&signsecset);
		}
		dns_rdataset_disassociate(&nsecset);
	}

	setnsec3parameters(db, version);

	/*
	 * Do we have a valid NSEC/NSEC3 chain?
	 */
	if (version->havensec3 || hasnsec) {
		version->secure = dns_db_secure;
	} else {
		version->secure = dns_db_insecure;
	}
}

/*%<
 * Walk the origin node looking for NSEC3PARAM records.
 * Cache the nsec3 parameters.
 */
static void
setnsec3parameters(dns_db_t *db, rbtdb_version_t *version) {
	dns_rbtnode_t *node;
	dns_rdata_nsec3param_t nsec3param;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_region_t region;
	isc_result_t result;
	rdatasetheader_t *header, *header_next;
	unsigned char *raw; /* RDATASLAB */
	unsigned int count, length;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	version->havensec3 = false;
	node = rbtdb->origin_node;
	NODE_LOCK(&(rbtdb->node_locks[node->locknum].lock),
		  isc_rwlocktype_read);
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		do {
			if (header->serial <= version->serial &&
			    !IGNORE(header)) {
				if (NONEXISTENT(header)) {
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);

		if (header != NULL &&
		    (header->type == dns_rdatatype_nsec3param)) {
			/*
			 * Find A NSEC3PARAM with a supported algorithm.
			 */
			raw = (unsigned char *)header + sizeof(*header);
			count = raw[0] * 256 + raw[1]; /* count */
			raw += DNS_RDATASET_COUNT + DNS_RDATASET_LENGTH;
			while (count-- > 0U) {
				length = raw[0] * 256 + raw[1];
				raw += DNS_RDATASET_ORDER + DNS_RDATASET_LENGTH;
				region.base = raw;
				region.length = length;
				raw += length;
				dns_rdata_fromregion(
					&rdata, rbtdb->common.rdclass,
					dns_rdatatype_nsec3param, &region);
				result = dns_rdata_tostruct(&rdata, &nsec3param,
							    NULL);
				INSIST(result == ISC_R_SUCCESS);
				dns_rdata_reset(&rdata);

				if (nsec3param.hash != DNS_NSEC3_UNKNOWNALG &&
				    !dns_nsec3_supportedhash(nsec3param.hash))
				{
					continue;
				}

				if (nsec3param.flags != 0) {
					continue;
				}

				memmove(version->salt, nsec3param.salt,
					nsec3param.salt_length);
				version->hash = nsec3param.hash;
				version->salt_length = nsec3param.salt_length;
				version->iterations = nsec3param.iterations;
				version->flags = nsec3param.flags;
				version->havensec3 = true;
				/*
				 * Look for a better algorithm than the
				 * unknown test algorithm.
				 */
				if (nsec3param.hash != DNS_NSEC3_UNKNOWNALG) {
					goto unlock;
				}
			}
		}
	}
unlock:
	NODE_UNLOCK(&(rbtdb->node_locks[node->locknum].lock),
		    isc_rwlocktype_read);
	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
}

static void
cleanup_dead_nodes_callback(isc_task_t *task, isc_event_t *event) {
	dns_rbtdb_t *rbtdb = event->ev_arg;
	bool again = false;
	unsigned int locknum;

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
	for (locknum = 0; locknum < rbtdb->node_lock_count; locknum++) {
		NODE_LOCK(&rbtdb->node_locks[locknum].lock,
			  isc_rwlocktype_write);
		cleanup_dead_nodes(rbtdb, locknum);
		if (ISC_LIST_HEAD(rbtdb->deadnodes[locknum]) != NULL) {
			again = true;
		}
		NODE_UNLOCK(&rbtdb->node_locks[locknum].lock,
			    isc_rwlocktype_write);
	}
	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
	if (again) {
		isc_task_send(task, &event);
	} else {
		isc_event_free(&event);
		if (isc_refcount_decrement(&rbtdb->references) == 1) {
			(void)isc_refcount_current(&rbtdb->references);
			maybe_free_rbtdb(rbtdb);
		}
	}
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp, bool commit) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_version_t *version, *cleanup_version, *least_greater;
	bool rollback = false;
	rbtdb_changedlist_t cleanup_list;
	rdatasetheaderlist_t resigned_list;
	rbtdb_changed_t *changed, *next_changed;
	rbtdb_serial_t serial;
	dns_rbtnode_t *rbtnode;
	rdatasetheader_t *header;

	REQUIRE(VALID_RBTDB(rbtdb));
	version = (rbtdb_version_t *)*versionp;
	INSIST(version->rbtdb == rbtdb);

	cleanup_version = NULL;
	ISC_LIST_INIT(cleanup_list);
	ISC_LIST_INIT(resigned_list);

	if (isc_refcount_decrement(&version->references) > 1) {
		/* typical and easy case first */
		if (commit) {
			RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_read);
			INSIST(!version->writer);
			RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_read);
		}
		goto end;
	}

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);
	serial = version->serial;
	if (version->writer) {
		if (commit) {
			unsigned cur_ref;
			rbtdb_version_t *cur_version;

			INSIST(version->commit_ok);
			INSIST(version == rbtdb->future_version);
			/*
			 * The current version is going to be replaced.
			 * Release the (likely last) reference to it from the
			 * DB itself and unlink it from the open list.
			 */
			cur_version = rbtdb->current_version;
			cur_ref = isc_refcount_decrement(
				&cur_version->references);
			if (cur_ref == 1) {
				(void)isc_refcount_current(
					&cur_version->references);
				if (cur_version->serial == rbtdb->least_serial)
				{
					INSIST(EMPTY(
						cur_version->changed_list));
				}
				UNLINK(rbtdb->open_versions, cur_version, link);
			}
			if (EMPTY(rbtdb->open_versions)) {
				/*
				 * We're going to become the least open
				 * version.
				 */
				make_least_version(rbtdb, version,
						   &cleanup_list);
			} else {
				/*
				 * Some other open version is the
				 * least version.  We can't cleanup
				 * records that were changed in this
				 * version because the older versions
				 * may still be in use by an open
				 * version.
				 *
				 * We can, however, discard the
				 * changed records for things that
				 * we've added that didn't exist in
				 * prior versions.
				 */
				cleanup_nondirty(version, &cleanup_list);
			}
			/*
			 * If the (soon to be former) current version
			 * isn't being used by anyone, we can clean
			 * it up.
			 */
			if (cur_ref == 1) {
				cleanup_version = cur_version;
				APPENDLIST(version->changed_list,
					   cleanup_version->changed_list, link);
			}
			/*
			 * Become the current version.
			 */
			version->writer = false;
			rbtdb->current_version = version;
			rbtdb->current_serial = version->serial;
			rbtdb->future_version = NULL;

			/*
			 * Keep the current version in the open list, and
			 * gain a reference for the DB itself (see the DB
			 * creation function below).  This must be the only
			 * case where we need to increment the counter from
			 * zero and need to use isc_refcount_increment0().
			 */
			INSIST(isc_refcount_increment0(&version->references) ==
			       0);
			PREPEND(rbtdb->open_versions, rbtdb->current_version,
				link);
			resigned_list = version->resigned_list;
			ISC_LIST_INIT(version->resigned_list);
		} else {
			/*
			 * We're rolling back this transaction.
			 */
			cleanup_list = version->changed_list;
			ISC_LIST_INIT(version->changed_list);
			resigned_list = version->resigned_list;
			ISC_LIST_INIT(version->resigned_list);
			rollback = true;
			cleanup_version = version;
			rbtdb->future_version = NULL;
		}
	} else {
		if (version != rbtdb->current_version) {
			/*
			 * There are no external or internal references
			 * to this version and it can be cleaned up.
			 */
			cleanup_version = version;

			/*
			 * Find the version with the least serial
			 * number greater than ours.
			 */
			least_greater = PREV(version, link);
			if (least_greater == NULL) {
				least_greater = rbtdb->current_version;
			}

			INSIST(version->serial < least_greater->serial);
			/*
			 * Is this the least open version?
			 */
			if (version->serial == rbtdb->least_serial) {
				/*
				 * Yes.  Install the new least open
				 * version.
				 */
				make_least_version(rbtdb, least_greater,
						   &cleanup_list);
			} else {
				/*
				 * Add any unexecuted cleanups to
				 * those of the least greater version.
				 */
				APPENDLIST(least_greater->changed_list,
					   version->changed_list, link);
			}
		} else if (version->serial == rbtdb->least_serial) {
			INSIST(EMPTY(version->changed_list));
		}
		UNLINK(rbtdb->open_versions, version, link);
	}
	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);

	if (cleanup_version != NULL) {
		INSIST(EMPTY(cleanup_version->changed_list));
		free_gluetable(cleanup_version);
		isc_rwlock_destroy(&cleanup_version->glue_rwlock);
		isc_rwlock_destroy(&cleanup_version->rwlock);
		isc_mem_put(rbtdb->common.mctx, cleanup_version,
			    sizeof(*cleanup_version));
	}

	/*
	 * Commit/rollback re-signed headers.
	 */
	for (header = HEAD(resigned_list); header != NULL;
	     header = HEAD(resigned_list)) {
		nodelock_t *lock;

		ISC_LIST_UNLINK(resigned_list, header, link);

		lock = &rbtdb->node_locks[header->node->locknum].lock;
		NODE_LOCK(lock, isc_rwlocktype_write);
		if (rollback && !IGNORE(header)) {
			isc_result_t result;
			result = resign_insert(rbtdb, header->node->locknum,
					       header);
			if (result != ISC_R_SUCCESS) {
				isc_log_write(dns_lctx,
					      DNS_LOGCATEGORY_DATABASE,
					      DNS_LOGMODULE_ZONE, ISC_LOG_ERROR,
					      "Unable to reinsert header to "
					      "re-signing heap: %s",
					      isc_result_totext(result));
			}
		}
		decrement_reference(rbtdb, header->node, isc_rwlocktype_write,
				    isc_rwlocktype_none, false);
		NODE_UNLOCK(lock, isc_rwlocktype_write);
	}

	if (!EMPTY(cleanup_list)) {
		isc_event_t *event = NULL;
		isc_rwlocktype_t tlock = isc_rwlocktype_none;

		if (rbtdb->task != NULL) {
			event = isc_event_allocate(rbtdb->common.mctx, NULL,
						   DNS_EVENT_RBTDEADNODES,
						   cleanup_dead_nodes_callback,
						   rbtdb, sizeof(isc_event_t));
		}
		if (event == NULL) {
			/*
			 * We acquire a tree write lock here in order to make
			 * sure that stale nodes will be removed in
			 * decrement_reference().  If we didn't have the lock,
			 * those nodes could miss the chance to be removed
			 * until the server stops.  The write lock is
			 * expensive, but this event should be rare enough
			 * to justify the cost.
			 */
			RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
			tlock = isc_rwlocktype_write;
		}

		for (changed = HEAD(cleanup_list); changed != NULL;
		     changed = next_changed) {
			nodelock_t *lock;

			next_changed = NEXT(changed, link);
			rbtnode = changed->node;
			lock = &rbtdb->node_locks[rbtnode->locknum].lock;

			NODE_LOCK(lock, isc_rwlocktype_write);
			/*
			 * This is a good opportunity to purge any dead nodes,
			 * so use it.
			 */
			if (event == NULL) {
				cleanup_dead_nodes(rbtdb, rbtnode->locknum);
			}

			if (rollback) {
				rollback_node(rbtnode, serial);
			}
			decrement_reference(rbtdb, rbtnode,
					    isc_rwlocktype_write, tlock, false);

			NODE_UNLOCK(lock, isc_rwlocktype_write);

			isc_mem_put(rbtdb->common.mctx, changed,
				    sizeof(*changed));
		}
		if (event != NULL) {
			isc_refcount_increment(&rbtdb->references);
			isc_task_send(rbtdb->task, &event);
		} else {
			RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
		}
	}

end:
	*versionp = NULL;
}

/*
 * Add the necessary magic for the wildcard name 'name'
 * to be found in 'rbtdb'.
 *
 * In order for wildcard matching to work correctly in
 * zone_find(), we must ensure that a node for the wildcarding
 * level exists in the database, and has its 'find_callback'
 * and 'wild' bits set.
 *
 * E.g. if the wildcard name is "*.sub.example." then we
 * must ensure that "sub.example." exists and is marked as
 * a wildcard level.
 *
 * tree_lock(write) must be held.
 */
static isc_result_t
add_wildcard_magic(dns_rbtdb_t *rbtdb, const dns_name_t *name) {
	isc_result_t result;
	dns_name_t foundname;
	dns_offsets_t offsets;
	unsigned int n;
	dns_rbtnode_t *node = NULL;

	dns_name_init(&foundname, offsets);
	n = dns_name_countlabels(name);
	INSIST(n >= 2);
	n--;
	dns_name_getlabelsequence(name, 1, n, &foundname);
	result = dns_rbt_addnode(rbtdb->tree, &foundname, &node);
	if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
		return (result);
	}
	if (result == ISC_R_SUCCESS) {
		node->nsec = DNS_RBT_NSEC_NORMAL;
	}
	node->find_callback = 1;
	node->wild = 1;
	return (ISC_R_SUCCESS);
}

/*
 * tree_lock(write) must be held.
 */
static isc_result_t
add_empty_wildcards(dns_rbtdb_t *rbtdb, const dns_name_t *name) {
	isc_result_t result;
	dns_name_t foundname;
	dns_offsets_t offsets;
	unsigned int n, l, i;

	dns_name_init(&foundname, offsets);
	n = dns_name_countlabels(name);
	l = dns_name_countlabels(&rbtdb->common.origin);
	i = l + 1;
	while (i < n) {
		dns_rbtnode_t *node = NULL; /* dummy */
		dns_name_getlabelsequence(name, n - i, i, &foundname);
		if (dns_name_iswildcard(&foundname)) {
			result = add_wildcard_magic(rbtdb, &foundname);
			if (result != ISC_R_SUCCESS) {
				return (result);
			}
			result = dns_rbt_addnode(rbtdb->tree, &foundname,
						 &node);
			if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
				return (result);
			}
			if (result == ISC_R_SUCCESS) {
				node->nsec = DNS_RBT_NSEC_NORMAL;
			}
		}
		i++;
	}
	return (ISC_R_SUCCESS);
}

static isc_result_t
findnodeintree(dns_rbtdb_t *rbtdb, dns_rbt_t *tree, const dns_name_t *name,
	       bool create, dns_dbnode_t **nodep) {
	dns_rbtnode_t *node = NULL;
	dns_name_t nodename;
	isc_result_t result;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;

	INSIST(tree == rbtdb->tree || tree == rbtdb->nsec3);

	dns_name_init(&nodename, NULL);
	RWLOCK(&rbtdb->tree_lock, locktype);
	result = dns_rbt_findnode(tree, name, NULL, &node, NULL,
				  DNS_RBTFIND_EMPTYDATA, NULL, NULL);
	if (result != ISC_R_SUCCESS) {
		RWUNLOCK(&rbtdb->tree_lock, locktype);
		if (!create) {
			if (result == DNS_R_PARTIALMATCH) {
				result = ISC_R_NOTFOUND;
			}
			return (result);
		}
		/*
		 * It would be nice to try to upgrade the lock instead of
		 * unlocking then relocking.
		 */
		locktype = isc_rwlocktype_write;
		RWLOCK(&rbtdb->tree_lock, locktype);
		node = NULL;
		result = dns_rbt_addnode(tree, name, &node);
		if (result == ISC_R_SUCCESS) {
			dns_rbt_namefromnode(node, &nodename);
			node->locknum = node->hashval % rbtdb->node_lock_count;
			if (tree == rbtdb->tree) {
				add_empty_wildcards(rbtdb, name);

				if (dns_name_iswildcard(name)) {
					result = add_wildcard_magic(rbtdb,
								    name);
					if (result != ISC_R_SUCCESS) {
						RWUNLOCK(&rbtdb->tree_lock,
							 locktype);
						return (result);
					}
				}
			}
			if (tree == rbtdb->nsec3) {
				node->nsec = DNS_RBT_NSEC_NSEC3;
			}
		} else if (result != ISC_R_EXISTS) {
			RWUNLOCK(&rbtdb->tree_lock, locktype);
			return (result);
		}
	}

	if (tree == rbtdb->nsec3) {
		INSIST(node->nsec == DNS_RBT_NSEC_NSEC3);
	}

	reactivate_node(rbtdb, node, locktype);

	RWUNLOCK(&rbtdb->tree_lock, locktype);

	*nodep = (dns_dbnode_t *)node;

	return (ISC_R_SUCCESS);
}

static isc_result_t
findnode(dns_db_t *db, const dns_name_t *name, bool create,
	 dns_dbnode_t **nodep) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	return (findnodeintree(rbtdb, rbtdb->tree, name, create, nodep));
}

static inline void
bind_rdataset(dns_rbtdb_t *rbtdb, dns_rbtnode_t *node, rdatasetheader_t *header,
	      isc_stdtime_t now, isc_rwlocktype_t locktype,
	      dns_rdataset_t *rdataset) {
	unsigned char *raw; /* RDATASLAB */
	bool stale = STALE(header);
	bool ancient = ANCIENT(header);

	/*
	 * Caller must be holding the node reader lock.
	 * XXXJT: technically, we need a writer lock, since we'll increment
	 * the header count below.  However, since the actual counter value
	 * doesn't matter, we prioritize performance here.  (We may want to
	 * use atomic increment when available).
	 */

	if (rdataset == NULL) {
		return;
	}

	new_reference(rbtdb, node, locktype);

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	/*
	 * Mark header stale or ancient if the RRset is no longer active.
	 */
	if (!ACTIVE(header, now)) {
		dns_ttl_t stale_ttl = header->rdh_ttl + rbtdb->serve_stale_ttl;
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		if (KEEPSTALE(rbtdb) && stale_ttl > now) {
			stale = true;
		} else {
			/*
			 * We are not keeping stale, or it is outside the
			 * stale window. Mark ancient, i.e. ready for cleanup.
			 */
			ancient = true;
		}
	}

	rdataset->methods = &rdataset_methods;
	rdataset->rdclass = rbtdb->common.rdclass;
	rdataset->type = RBTDB_RDATATYPE_BASE(header->type);
	rdataset->covers = RBTDB_RDATATYPE_EXT(header->type);
	rdataset->ttl = header->rdh_ttl - now;
	rdataset->trust = header->trust;

	if (NEGATIVE(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_NEGATIVE;
	}
	if (NXDOMAIN(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_NXDOMAIN;
	}
	if (OPTOUT(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_OPTOUT;
	}
	if (PREFETCH(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_PREFETCH;
	}

	if (stale && !ancient) {
		dns_ttl_t stale_ttl = header->rdh_ttl + rbtdb->serve_stale_ttl;
		if (stale_ttl > now) {
			rdataset->ttl = stale_ttl - now;
		} else {
			rdataset->ttl = 0;
		}
		if (STALE_WINDOW(header)) {
			rdataset->attributes |= DNS_RDATASETATTR_STALE_WINDOW;
		}
		rdataset->attributes |= DNS_RDATASETATTR_STALE;
	} else if (!ACTIVE(header, now)) {
		rdataset->attributes |= DNS_RDATASETATTR_ANCIENT;
		rdataset->ttl = header->rdh_ttl;
	}

	rdataset->private1 = rbtdb;
	rdataset->private2 = node;
	raw = (unsigned char *)header + sizeof(*header);
	rdataset->private3 = raw;
	rdataset->count = atomic_fetch_add_relaxed(&header->count, 1);
	if (rdataset->count == UINT32_MAX) {
		rdataset->count = 0;
	}

	/*
	 * Reset iterator state.
	 */
	rdataset->privateuint4 = 0;
	rdataset->private5 = NULL;

	/*
	 * Add noqname proof.
	 */
	rdataset->private6 = header->noqname;
	if (rdataset->private6 != NULL) {
		rdataset->attributes |= DNS_RDATASETATTR_NOQNAME;
	}
	rdataset->private7 = header->closest;
	if (rdataset->private7 != NULL) {
		rdataset->attributes |= DNS_RDATASETATTR_CLOSEST;
	}

	/*
	 * Copy out re-signing information.
	 */
	if (RESIGN(header)) {
		rdataset->attributes |= DNS_RDATASETATTR_RESIGN;
		rdataset->resign = (header->resign << 1) | header->resign_lsb;
	} else {
		rdataset->resign = 0;
	}
}

static inline isc_result_t
setup_delegation(rbtdb_search_t *search, dns_dbnode_t **nodep,
		 dns_name_t *foundname, dns_rdataset_t *rdataset,
		 dns_rdataset_t *sigrdataset) {
	dns_name_t *zcname;
	rbtdb_rdatatype_t type;
	dns_rbtnode_t *node;

	/*
	 * The caller MUST NOT be holding any node locks.
	 */

	node = search->zonecut;
	type = search->zonecut_rdataset->type;

	/*
	 * If we have to set foundname, we do it before anything else.
	 * If we were to set foundname after we had set nodep or bound the
	 * rdataset, then we'd have to undo that work if dns_name_copy()
	 * failed.  By setting foundname first, there's nothing to undo if
	 * we have trouble.
	 */
	if (foundname != NULL && search->copy_name) {
		zcname = dns_fixedname_name(&search->zonecut_name);
		dns_name_copy(zcname, foundname);
	}
	if (nodep != NULL) {
		/*
		 * Note that we don't have to increment the node's reference
		 * count here because we're going to use the reference we
		 * already have in the search block.
		 */
		*nodep = node;
		search->need_cleanup = false;
	}
	if (rdataset != NULL) {
		NODE_LOCK(&(search->rbtdb->node_locks[node->locknum].lock),
			  isc_rwlocktype_read);
		bind_rdataset(search->rbtdb, node, search->zonecut_rdataset,
			      search->now, isc_rwlocktype_read, rdataset);
		if (sigrdataset != NULL && search->zonecut_sigrdataset != NULL)
		{
			bind_rdataset(search->rbtdb, node,
				      search->zonecut_sigrdataset, search->now,
				      isc_rwlocktype_read, sigrdataset);
		}
		NODE_UNLOCK(&(search->rbtdb->node_locks[node->locknum].lock),
			    isc_rwlocktype_read);
	}

	if (type == dns_rdatatype_dname) {
		return (DNS_R_DNAME);
	}
	return (DNS_R_DELEGATION);
}

static bool
check_stale_header(dns_rbtnode_t *node, rdatasetheader_t *header,
		   isc_rwlocktype_t *locktype, nodelock_t *lock,
		   rbtdb_search_t *search, rdatasetheader_t **header_prev) {
	if (!ACTIVE(header, search->now)) {
		dns_ttl_t stale = header->rdh_ttl +
				  search->rbtdb->serve_stale_ttl;
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		RDATASET_ATTR_CLR(header, RDATASET_ATTR_STALE_WINDOW);
		if (!ZEROTTL(header) && KEEPSTALE(search->rbtdb) &&
		    stale > search->now) {
			mark_header_stale(search->rbtdb, header);
			*header_prev = header;
			/*
			 * If DNS_DBFIND_STALESTART is set then it means we
			 * failed to resolve the name during recursion, in
			 * this case we mark the time in which the refresh
			 * failed.
			 */
			if ((search->options & DNS_DBFIND_STALESTART) != 0) {
				atomic_store_release(
					&header->last_refresh_fail_ts,
					search->now);
			} else if ((search->options &
				    DNS_DBFIND_STALEENABLED) != 0 &&
				   search->now <
					   (atomic_load_acquire(
						    &header->last_refresh_fail_ts) +
					    search->rbtdb->serve_stale_refresh))
			{
				/*
				 * If we are within interval between last
				 * refresh failure time + 'stale-refresh-time',
				 * then don't skip this stale entry but use it
				 * instead.
				 */
				RDATASET_ATTR_SET(header,
						  RDATASET_ATTR_STALE_WINDOW);
				return (false);
			} else if ((search->options &
				    DNS_DBFIND_STALETIMEOUT) != 0) {
				/*
				 * We want stale RRset due to timeout, so we
				 * don't skip it.
				 */
				return (false);
			}
			return ((search->options & DNS_DBFIND_STALEOK) == 0);
		}

		/*
		 * This rdataset is stale.  If no one else is using the
		 * node, we can clean it up right now, otherwise we mark
		 * it as ancient, and the node as dirty, so it will get
		 * cleaned up later.
		 */
		if ((header->rdh_ttl < search->now - RBTDB_VIRTUAL) &&
		    (*locktype == isc_rwlocktype_write ||
		     NODE_TRYUPGRADE(lock) == ISC_R_SUCCESS))
		{
			/*
			 * We update the node's status only when we can
			 * get write access; otherwise, we leave others
			 * to this work.  Periodical cleaning will
			 * eventually take the job as the last resort.
			 * We won't downgrade the lock, since other
			 * rdatasets are probably stale, too.
			 */
			*locktype = isc_rwlocktype_write;

			if (isc_refcount_current(&node->references) == 0) {
				isc_mem_t *mctx;

				/*
				 * header->down can be non-NULL if the
				 * refcount has just decremented to 0
				 * but decrement_reference() has not
				 * performed clean_cache_node(), in
				 * which case we need to purge the stale
				 * headers first.
				 */
				mctx = search->rbtdb->common.mctx;
				clean_stale_headers(search->rbtdb, mctx,
						    header);
				if (*header_prev != NULL) {
					(*header_prev)->next = header->next;
				} else {
					node->data = header->next;
				}
				free_rdataset(search->rbtdb, mctx, header);
			} else {
				mark_header_ancient(search->rbtdb, header);
				*header_prev = header;
			}
		} else {
			*header_prev = header;
		}
		return (true);
	}
	return (false);
}

static isc_result_t
cache_zonecut_callback(dns_rbtnode_t *node, dns_name_t *name, void *arg) {
	rbtdb_search_t *search = arg;
	rdatasetheader_t *header, *header_prev, *header_next;
	rdatasetheader_t *dname_header, *sigdname_header;
	isc_result_t result;
	nodelock_t *lock;
	isc_rwlocktype_t locktype;

	/* XXX comment */

	REQUIRE(search->zonecut == NULL);

	/*
	 * Keep compiler silent.
	 */
	UNUSED(name);

	lock = &(search->rbtdb->node_locks[node->locknum].lock);
	locktype = isc_rwlocktype_read;
	NODE_LOCK(lock, locktype);

	/*
	 * Look for a DNAME or RRSIG DNAME rdataset.
	 */
	dname_header = NULL;
	sigdname_header = NULL;
	header_prev = NULL;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &locktype, lock, search,
				       &header_prev)) {
			/* Do nothing. */
		} else if (header->type == dns_rdatatype_dname &&
			   EXISTS(header) && !ANCIENT(header))
		{
			dname_header = header;
			header_prev = header;
		} else if (header->type == RBTDB_RDATATYPE_SIGDNAME &&
			   EXISTS(header) && !ANCIENT(header))
		{
			sigdname_header = header;
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (dname_header != NULL &&
	    (!DNS_TRUST_PENDING(dname_header->trust) ||
	     (search->options & DNS_DBFIND_PENDINGOK) != 0))
	{
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_rdataset will still be valid later.
		 */
		new_reference(search->rbtdb, node, locktype);
		search->zonecut = node;
		search->zonecut_rdataset = dname_header;
		search->zonecut_sigrdataset = sigdname_header;
		search->need_cleanup = true;
		result = DNS_R_PARTIALMATCH;
	} else {
		result = DNS_R_CONTINUE;
	}

	NODE_UNLOCK(lock, locktype);

	return (result);
}

static inline isc_result_t
find_deepest_zonecut(rbtdb_search_t *search, dns_rbtnode_t *node,
		     dns_dbnode_t **nodep, dns_name_t *foundname,
		     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	unsigned int i;
	dns_rbtnode_t *level_node;
	rdatasetheader_t *header, *header_prev, *header_next;
	rdatasetheader_t *found, *foundsig;
	isc_result_t result = ISC_R_NOTFOUND;
	dns_name_t name;
	dns_rbtdb_t *rbtdb;
	bool done;
	nodelock_t *lock;
	isc_rwlocktype_t locktype;

	/*
	 * Caller must be holding the tree lock.
	 */

	rbtdb = search->rbtdb;
	i = search->chain.level_matches;
	done = false;
	do {
		locktype = isc_rwlocktype_read;
		lock = &rbtdb->node_locks[node->locknum].lock;
		NODE_LOCK(lock, locktype);

		/*
		 * Look for NS and RRSIG NS rdatasets.
		 */
		found = NULL;
		foundsig = NULL;
		header_prev = NULL;
		for (header = node->data; header != NULL; header = header_next)
		{
			header_next = header->next;
			if (check_stale_header(node, header, &locktype, lock,
					       search, &header_prev)) {
				/* Do nothing. */
			} else if (EXISTS(header) && !ANCIENT(header)) {
				/*
				 * We've found an extant rdataset.  See if
				 * we're interested in it.
				 */
				if (header->type == dns_rdatatype_ns) {
					found = header;
					if (foundsig != NULL) {
						break;
					}
				} else if (header->type ==
					   RBTDB_RDATATYPE_SIGNS) {
					foundsig = header;
					if (found != NULL) {
						break;
					}
				}
				header_prev = header;
			} else {
				header_prev = header;
			}
		}

		if (found != NULL) {
			/*
			 * If we have to set foundname, we do it before
			 * anything else.  If we were to set foundname after
			 * we had set nodep or bound the rdataset, then we'd
			 * have to undo that work if dns_name_concatenate()
			 * failed.  By setting foundname first, there's
			 * nothing to undo if we have trouble.
			 */
			if (foundname != NULL) {
				dns_name_init(&name, NULL);
				dns_rbt_namefromnode(node, &name);
				dns_name_copy(&name, foundname);
				while (i > 0) {
					i--;
					level_node = search->chain.levels[i];
					dns_name_init(&name, NULL);
					dns_rbt_namefromnode(level_node, &name);
					result = dns_name_concatenate(
						foundname, &name, foundname,
						NULL);
					if (result != ISC_R_SUCCESS) {
						if (nodep != NULL) {
							*nodep = NULL;
						}
						goto node_exit;
					}
				}
			}
			result = DNS_R_DELEGATION;
			if (nodep != NULL) {
				new_reference(search->rbtdb, node, locktype);
				*nodep = node;
			}
			bind_rdataset(search->rbtdb, node, found, search->now,
				      locktype, rdataset);
			if (foundsig != NULL) {
				bind_rdataset(search->rbtdb, node, foundsig,
					      search->now, locktype,
					      sigrdataset);
			}
			if (need_headerupdate(found, search->now) ||
			    (foundsig != NULL &&
			     need_headerupdate(foundsig, search->now)))
			{
				if (locktype != isc_rwlocktype_write) {
					NODE_UNLOCK(lock, locktype);
					NODE_LOCK(lock, isc_rwlocktype_write);
					locktype = isc_rwlocktype_write;
					POST(locktype);
				}
				if (need_headerupdate(found, search->now)) {
					update_header(search->rbtdb, found,
						      search->now);
				}
				if (foundsig != NULL &&
				    need_headerupdate(foundsig, search->now)) {
					update_header(search->rbtdb, foundsig,
						      search->now);
				}
			}
		}

	node_exit:
		NODE_UNLOCK(lock, locktype);

		if (found == NULL && i > 0) {
			i--;
			node = search->chain.levels[i];
		} else {
			done = true;
		}
	} while (!done);

	return (result);
}

static isc_result_t
find_coveringnsec(rbtdb_search_t *search, dns_dbnode_t **nodep,
		  isc_stdtime_t now, dns_name_t *foundname,
		  dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	dns_rbtnode_t *node;
	rdatasetheader_t *header, *header_next, *header_prev;
	rdatasetheader_t *found, *foundsig;
	bool empty_node;
	isc_result_t result;
	dns_fixedname_t fname, forigin;
	dns_name_t *name, *origin;
	rbtdb_rdatatype_t matchtype, sigmatchtype;
	nodelock_t *lock;
	isc_rwlocktype_t locktype;
	dns_rbtnodechain_t chain;

	chain = search->chain;

	matchtype = RBTDB_RDATATYPE_VALUE(dns_rdatatype_nsec, 0);
	sigmatchtype = RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig,
					     dns_rdatatype_nsec);

	do {
		node = NULL;
		name = dns_fixedname_initname(&fname);
		origin = dns_fixedname_initname(&forigin);
		result = dns_rbtnodechain_current(&chain, name, origin, &node);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		locktype = isc_rwlocktype_read;
		lock = &(search->rbtdb->node_locks[node->locknum].lock);
		NODE_LOCK(lock, locktype);
		found = NULL;
		foundsig = NULL;
		empty_node = true;
		header_prev = NULL;
		for (header = node->data; header != NULL; header = header_next)
		{
			header_next = header->next;
			if (check_stale_header(node, header, &locktype, lock,
					       search, &header_prev)) {
				continue;
			}
			if (NONEXISTENT(header) ||
			    RBTDB_RDATATYPE_BASE(header->type) == 0) {
				header_prev = header;
				continue;
			}
			/*
			 * Don't stop on provable noqname / RRSIG.
			 */
			if (header->noqname == NULL &&
			    RBTDB_RDATATYPE_BASE(header->type) !=
				    dns_rdatatype_rrsig)
			{
				empty_node = false;
			}
			if (header->type == matchtype) {
				found = header;
			} else if (header->type == sigmatchtype) {
				foundsig = header;
			}
			header_prev = header;
		}
		if (found != NULL) {
			result = dns_name_concatenate(name, origin, foundname,
						      NULL);
			if (result != ISC_R_SUCCESS) {
				goto unlock_node;
			}
			bind_rdataset(search->rbtdb, node, found, now, locktype,
				      rdataset);
			if (foundsig != NULL) {
				bind_rdataset(search->rbtdb, node, foundsig,
					      now, locktype, sigrdataset);
			}
			new_reference(search->rbtdb, node, locktype);
			*nodep = node;
			result = DNS_R_COVERINGNSEC;
		} else if (!empty_node) {
			result = ISC_R_NOTFOUND;
		} else {
			result = dns_rbtnodechain_prev(&chain, NULL, NULL);
		}
	unlock_node:
		NODE_UNLOCK(lock, locktype);
	} while (empty_node && result == ISC_R_SUCCESS);
	return (result);
}

static isc_result_t
cache_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	   dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	   dns_dbnode_t **nodep, dns_name_t *foundname,
	   dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	dns_rbtnode_t *node = NULL;
	isc_result_t result;
	rbtdb_search_t search;
	bool cname_ok = true;
	bool empty_node;
	nodelock_t *lock;
	isc_rwlocktype_t locktype;
	rdatasetheader_t *header, *header_prev, *header_next;
	rdatasetheader_t *found, *nsheader;
	rdatasetheader_t *foundsig, *nssig, *cnamesig;
	rdatasetheader_t *update, *updatesig;
	rdatasetheader_t *nsecheader, *nsecsig;
	rbtdb_rdatatype_t sigtype, negtype;

	UNUSED(version);

	search.rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(search.rbtdb));
	REQUIRE(version == NULL);

	if (now == 0) {
		isc_stdtime_get(&now);
	}

	search.rbtversion = NULL;
	search.serial = 1;
	search.options = options;
	search.copy_name = false;
	search.need_cleanup = false;
	search.wild = false;
	search.zonecut = NULL;
	dns_fixedname_init(&search.zonecut_name);
	dns_rbtnodechain_init(&search.chain);
	search.now = now;
	update = NULL;
	updatesig = NULL;

	RWLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	/*
	 * Search down from the root of the tree.  If, while going down, we
	 * encounter a callback node, cache_zonecut_callback() will search the
	 * rdatasets at the zone cut for a DNAME rdataset.
	 */
	result = dns_rbt_findnode(search.rbtdb->tree, name, foundname, &node,
				  &search.chain, DNS_RBTFIND_EMPTYDATA,
				  cache_zonecut_callback, &search);

	if (result == DNS_R_PARTIALMATCH) {
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0) {
			result = find_coveringnsec(&search, nodep, now,
						   foundname, rdataset,
						   sigrdataset);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		if (search.zonecut != NULL) {
			result = setup_delegation(&search, nodep, foundname,
						  rdataset, sigrdataset);
			goto tree_exit;
		} else {
		find_ns:
			result = find_deepest_zonecut(&search, node, nodep,
						      foundname, rdataset,
						      sigrdataset);
			goto tree_exit;
		}
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	}

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC4035, section 2.5 and RFC3007).
	 *
	 * We don't check for RRSIG, because we don't store RRSIG records
	 * directly.
	 */
	if (type == dns_rdatatype_key || type == dns_rdatatype_nsec) {
		cname_ok = false;
	}

	/*
	 * We now go looking for rdata...
	 */

	lock = &(search.rbtdb->node_locks[node->locknum].lock);
	locktype = isc_rwlocktype_read;
	NODE_LOCK(lock, locktype);

	found = NULL;
	foundsig = NULL;
	sigtype = RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, type);
	negtype = RBTDB_RDATATYPE_VALUE(0, type);
	nsheader = NULL;
	nsecheader = NULL;
	nssig = NULL;
	nsecsig = NULL;
	cnamesig = NULL;
	empty_node = true;
	header_prev = NULL;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &locktype, lock, &search,
				       &header_prev)) {
			/* Do nothing. */
		} else if (EXISTS(header) && !ANCIENT(header)) {
			/*
			 * We now know that there is at least one active
			 * non-stale rdataset at this node.
			 */
			empty_node = false;

			/*
			 * If we found a type we were looking for, remember
			 * it.
			 */
			if (header->type == type ||
			    (type == dns_rdatatype_any &&
			     RBTDB_RDATATYPE_BASE(header->type) != 0) ||
			    (cname_ok && header->type == dns_rdatatype_cname))
			{
				/*
				 * We've found the answer.
				 */
				found = header;
				if (header->type == dns_rdatatype_cname &&
				    cname_ok && cnamesig != NULL) {
					/*
					 * If we've already got the
					 * CNAME RRSIG, use it.
					 */
					foundsig = cnamesig;
				}
			} else if (header->type == sigtype) {
				/*
				 * We've found the RRSIG rdataset for our
				 * target type.  Remember it.
				 */
				foundsig = header;
			} else if (header->type == RBTDB_RDATATYPE_NCACHEANY ||
				   header->type == negtype) {
				/*
				 * We've found a negative cache entry.
				 */
				found = header;
			} else if (header->type == dns_rdatatype_ns) {
				/*
				 * Remember a NS rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				nsheader = header;
			} else if (header->type == RBTDB_RDATATYPE_SIGNS) {
				/*
				 * If we need the NS rdataset, we'll also
				 * need its signature.
				 */
				nssig = header;
			} else if (header->type == dns_rdatatype_nsec) {
				nsecheader = header;
			} else if (header->type == RBTDB_RDATATYPE_SIGNSEC) {
				nsecsig = header;
			} else if (cname_ok &&
				   header->type == RBTDB_RDATATYPE_SIGCNAME) {
				/*
				 * If we get a CNAME match, we'll also need
				 * its signature.
				 */
				cnamesig = header;
			}
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * extant rdatasets.  That means that this node doesn't
		 * meaningfully exist, and that we really have a partial match.
		 */
		NODE_UNLOCK(lock, locktype);
		goto find_ns;
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (found == NULL ||
	    (DNS_TRUST_ADDITIONAL(found->trust) &&
	     ((options & DNS_DBFIND_ADDITIONALOK) == 0)) ||
	    (found->trust == dns_trust_glue &&
	     ((options & DNS_DBFIND_GLUEOK) == 0)) ||
	    (DNS_TRUST_PENDING(found->trust) &&
	     ((options & DNS_DBFIND_PENDINGOK) == 0)))
	{
		/*
		 * Return covering NODATA NSEC record.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    nsecheader != NULL) {
			if (nodep != NULL) {
				new_reference(search.rbtdb, node, locktype);
				*nodep = node;
			}
			bind_rdataset(search.rbtdb, node, nsecheader,
				      search.now, locktype, rdataset);
			if (need_headerupdate(nsecheader, search.now)) {
				update = nsecheader;
			}
			if (nsecsig != NULL) {
				bind_rdataset(search.rbtdb, node, nsecsig,
					      search.now, locktype,
					      sigrdataset);
				if (need_headerupdate(nsecsig, search.now)) {
					updatesig = nsecsig;
				}
			}
			result = DNS_R_COVERINGNSEC;
			goto node_exit;
		}

		/*
		 * If there is an NS rdataset at this node, then this is the
		 * deepest zone cut.
		 */
		if (nsheader != NULL) {
			if (nodep != NULL) {
				new_reference(search.rbtdb, node, locktype);
				*nodep = node;
			}
			bind_rdataset(search.rbtdb, node, nsheader, search.now,
				      locktype, rdataset);
			if (need_headerupdate(nsheader, search.now)) {
				update = nsheader;
			}
			if (nssig != NULL) {
				bind_rdataset(search.rbtdb, node, nssig,
					      search.now, locktype,
					      sigrdataset);
				if (need_headerupdate(nssig, search.now)) {
					updatesig = nssig;
				}
			}
			result = DNS_R_DELEGATION;
			goto node_exit;
		}

		/*
		 * Go find the deepest zone cut.
		 */
		NODE_UNLOCK(lock, locktype);
		goto find_ns;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */

	if (nodep != NULL) {
		new_reference(search.rbtdb, node, locktype);
		*nodep = node;
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	} else if (type != found->type && type != dns_rdatatype_any &&
		   found->type == dns_rdatatype_cname)
	{
		/*
		 * We weren't doing an ANY query and we found a CNAME instead
		 * of the type we were looking for, so we need to indicate
		 * that result to the caller.
		 */
		result = DNS_R_CNAME;
	} else {
		/*
		 * An ordinary successful query!
		 */
		result = ISC_R_SUCCESS;
	}

	if (type != dns_rdatatype_any || result == DNS_R_NCACHENXDOMAIN ||
	    result == DNS_R_NCACHENXRRSET)
	{
		bind_rdataset(search.rbtdb, node, found, search.now, locktype,
			      rdataset);
		if (need_headerupdate(found, search.now)) {
			update = found;
		}
		if (!NEGATIVE(found) && foundsig != NULL) {
			bind_rdataset(search.rbtdb, node, foundsig, search.now,
				      locktype, sigrdataset);
			if (need_headerupdate(foundsig, search.now)) {
				updatesig = foundsig;
			}
		}
	}

node_exit:
	if ((update != NULL || updatesig != NULL) &&
	    locktype != isc_rwlocktype_write) {
		NODE_UNLOCK(lock, locktype);
		NODE_LOCK(lock, isc_rwlocktype_write);
		locktype = isc_rwlocktype_write;
		POST(locktype);
	}
	if (update != NULL && need_headerupdate(update, search.now)) {
		update_header(search.rbtdb, update, search.now);
	}
	if (updatesig != NULL && need_headerupdate(updatesig, search.now)) {
		update_header(search.rbtdb, updatesig, search.now);
	}

	NODE_UNLOCK(lock, locktype);

tree_exit:
	RWUNLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	if (search.need_cleanup) {
		node = search.zonecut;
		INSIST(node != NULL);
		lock = &(search.rbtdb->node_locks[node->locknum].lock);

		NODE_LOCK(lock, isc_rwlocktype_read);
		decrement_reference(search.rbtdb, node, isc_rwlocktype_read,
				    isc_rwlocktype_none, false);
		NODE_UNLOCK(lock, isc_rwlocktype_read);
	}

	dns_rbtnodechain_reset(&search.chain);

	update_cachestats(search.rbtdb, result);
	return (result);
}

static isc_result_t
cache_findzonecut(dns_db_t *db, const dns_name_t *name, unsigned int options,
		  isc_stdtime_t now, dns_dbnode_t **nodep,
		  dns_name_t *foundname, dns_name_t *dcname,
		  dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	dns_rbtnode_t *node = NULL;
	nodelock_t *lock;
	isc_result_t result;
	rbtdb_search_t search;
	rdatasetheader_t *header, *header_prev, *header_next;
	rdatasetheader_t *found, *foundsig;
	unsigned int rbtoptions = DNS_RBTFIND_EMPTYDATA;
	isc_rwlocktype_t locktype;
	bool dcnull = (dcname == NULL);

	search.rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(search.rbtdb));

	if (now == 0) {
		isc_stdtime_get(&now);
	}

	search.rbtversion = NULL;
	search.serial = 1;
	search.options = options;
	search.copy_name = false;
	search.need_cleanup = false;
	search.wild = false;
	search.zonecut = NULL;
	dns_fixedname_init(&search.zonecut_name);
	dns_rbtnodechain_init(&search.chain);
	search.now = now;

	if (dcnull) {
		dcname = foundname;
	}

	if ((options & DNS_DBFIND_NOEXACT) != 0) {
		rbtoptions |= DNS_RBTFIND_NOEXACT;
	}

	RWLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_rbt_findnode(search.rbtdb->tree, name, dcname, &node,
				  &search.chain, rbtoptions, NULL, &search);

	if (result == DNS_R_PARTIALMATCH) {
		result = find_deepest_zonecut(&search, node, nodep, foundname,
					      rdataset, sigrdataset);
		goto tree_exit;
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	} else if (!dcnull) {
		dns_name_copy(dcname, foundname);
	}

	/*
	 * We now go looking for an NS rdataset at the node.
	 */

	lock = &(search.rbtdb->node_locks[node->locknum].lock);
	locktype = isc_rwlocktype_read;
	NODE_LOCK(lock, locktype);

	found = NULL;
	foundsig = NULL;
	header_prev = NULL;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (check_stale_header(node, header, &locktype, lock, &search,
				       &header_prev)) {
			/*
			 * The function dns_rbt_findnode found us the a matching
			 * node for 'name' and stored the result in 'dcname'.
			 * This is the deepest known zonecut in our database.
			 * However, this node may be stale and if serve-stale
			 * is not enabled (in other words 'stale-answer-enable'
			 * is set to no), this node may not be used as a
			 * zonecut we know about. If so, find the deepest
			 * zonecut from this node up and return that instead.
			 */
			NODE_UNLOCK(lock, locktype);
			result = find_deepest_zonecut(&search, node, nodep,
						      foundname, rdataset,
						      sigrdataset);
			dns_name_copy(foundname, dcname);
			goto tree_exit;
		} else if (EXISTS(header) && !ANCIENT(header)) {
			/*
			 * If we found a type we were looking for, remember
			 * it.
			 */
			if (header->type == dns_rdatatype_ns) {
				/*
				 * Remember a NS rdataset even if we're
				 * not specifically looking for it, because
				 * we might need it later.
				 */
				found = header;
			} else if (header->type == RBTDB_RDATATYPE_SIGNS) {
				/*
				 * If we need the NS rdataset, we'll also
				 * need its signature.
				 */
				foundsig = header;
			}
			header_prev = header;
		} else {
			header_prev = header;
		}
	}

	if (found == NULL) {
		/*
		 * No NS records here.
		 */
		NODE_UNLOCK(lock, locktype);
		result = find_deepest_zonecut(&search, node, nodep, foundname,
					      rdataset, sigrdataset);
		goto tree_exit;
	}

	if (nodep != NULL) {
		new_reference(search.rbtdb, node, locktype);
		*nodep = node;
	}

	bind_rdataset(search.rbtdb, node, found, search.now, locktype,
		      rdataset);
	if (foundsig != NULL) {
		bind_rdataset(search.rbtdb, node, foundsig, search.now,
			      locktype, sigrdataset);
	}

	if (need_headerupdate(found, search.now) ||
	    (foundsig != NULL && need_headerupdate(foundsig, search.now)))
	{
		if (locktype != isc_rwlocktype_write) {
			NODE_UNLOCK(lock, locktype);
			NODE_LOCK(lock, isc_rwlocktype_write);
			locktype = isc_rwlocktype_write;
			POST(locktype);
		}
		if (need_headerupdate(found, search.now)) {
			update_header(search.rbtdb, found, search.now);
		}
		if (foundsig != NULL && need_headerupdate(foundsig, search.now))
		{
			update_header(search.rbtdb, foundsig, search.now);
		}
	}

	NODE_UNLOCK(lock, locktype);

tree_exit:
	RWUNLOCK(&search.rbtdb->tree_lock, isc_rwlocktype_read);

	INSIST(!search.need_cleanup);

	dns_rbtnodechain_reset(&search.chain);

	if (result == DNS_R_DELEGATION) {
		result = ISC_R_SUCCESS;
	}

	return (result);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *node = (dns_rbtnode_t *)source;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&node->references);

	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *node;
	bool want_free = false;
	bool inactive = false;
	rbtdb_nodelock_t *nodelock;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(targetp != NULL && *targetp != NULL);

	node = (dns_rbtnode_t *)(*targetp);
	nodelock = &rbtdb->node_locks[node->locknum];

	NODE_LOCK(&nodelock->lock, isc_rwlocktype_read);

	if (decrement_reference(rbtdb, node, isc_rwlocktype_read,
				isc_rwlocktype_none, false))
	{
		if (isc_refcount_current(&nodelock->references) == 0 &&
		    nodelock->exiting) {
			inactive = true;
		}
	}

	NODE_UNLOCK(&nodelock->lock, isc_rwlocktype_read);

	*targetp = NULL;

	if (inactive) {
		RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);
		rbtdb->active--;
		if (rbtdb->active == 0) {
			want_free = true;
		}
		RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);
		if (want_free) {
			char buf[DNS_NAME_FORMATSIZE];
			if (dns_name_dynamic(&rbtdb->common.origin)) {
				dns_name_format(&rbtdb->common.origin, buf,
						sizeof(buf));
			} else {
				strlcpy(buf, "<UNKNOWN>", sizeof(buf));
			}
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
				      "calling free_rbtdb(%s)", buf);
			free_rbtdb(rbtdb, true, NULL);
		}
	}
}

static isc_result_t
expirenode(dns_db_t *db, dns_dbnode_t *node, isc_stdtime_t now) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = node;
	rdatasetheader_t *header;
	bool force_expire = false;
	/*
	 * These are the category and module used by the cache cleaner.
	 */
	bool log = false;
	isc_logcategory_t *category = DNS_LOGCATEGORY_DATABASE;
	isc_logmodule_t *module = DNS_LOGMODULE_CACHE;
	int level = ISC_LOG_DEBUG(2);
	char printname[DNS_NAME_FORMATSIZE];

	REQUIRE(VALID_RBTDB(rbtdb));

	/*
	 * Caller must hold a tree lock.
	 */

	if (now == 0) {
		isc_stdtime_get(&now);
	}

	if (isc_mem_isovermem(rbtdb->common.mctx)) {
		/*
		 * Force expire with 25% probability.
		 * XXXDCL Could stand to have a better policy, like LRU.
		 */
		force_expire = (rbtnode->down == NULL &&
				(isc_random32() % 4) == 0);

		/*
		 * Note that 'log' can be true IFF overmem is also true.
		 * overmem can currently only be true for cache
		 * databases -- hence all of the "overmem cache" log strings.
		 */
		log = isc_log_wouldlog(dns_lctx, level);
		if (log) {
			isc_log_write(
				dns_lctx, category, module, level,
				"overmem cache: %s %s",
				force_expire ? "FORCE" : "check",
				dns_rbt_formatnodename(rbtnode, printname,
						       sizeof(printname)));
		}
	}

	/*
	 * We may not need write access, but this code path is not performance
	 * sensitive, so it should be okay to always lock as a writer.
	 */
	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);

	for (header = rbtnode->data; header != NULL; header = header->next) {
		if (header->rdh_ttl + rbtdb->serve_stale_ttl <=
		    now - RBTDB_VIRTUAL) {
			/*
			 * We don't check if refcurrent(rbtnode) == 0 and try
			 * to free like we do in cache_find(), because
			 * refcurrent(rbtnode) must be non-zero.  This is so
			 * because 'node' is an argument to the function.
			 */
			mark_header_ancient(rbtdb, header);
			if (log) {
				isc_log_write(dns_lctx, category, module, level,
					      "overmem cache: ancient %s",
					      printname);
			}
		} else if (force_expire) {
			if (!RETAIN(header)) {
				set_ttl(rbtdb, header, 0);
				mark_header_ancient(rbtdb, header);
			} else if (log) {
				isc_log_write(dns_lctx, category, module, level,
					      "overmem cache: "
					      "reprieve by RETAIN() %s",
					      printname);
			}
		} else if (isc_mem_isovermem(rbtdb->common.mctx) && log) {
			isc_log_write(dns_lctx, category, module, level,
				      "overmem cache: saved %s", printname);
		}
	}

	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);

	return (ISC_R_SUCCESS);
}

static void
overmem(dns_db_t *db, bool over) {
	/* This is an empty callback.  See adb.c:water() */

	UNUSED(db);
	UNUSED(over);

	return;
}

static void
printnode(dns_db_t *db, dns_dbnode_t *node, FILE *out) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = node;
	bool first;
	uint32_t refs;

	REQUIRE(VALID_RBTDB(rbtdb));

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_read);

	refs = isc_refcount_current(&rbtnode->references);
	fprintf(out, "node %p, %" PRIu32 " references, locknum = %u\n", rbtnode,
		refs, rbtnode->locknum);
	if (rbtnode->data != NULL) {
		rdatasetheader_t *current, *top_next;

		for (current = rbtnode->data; current != NULL;
		     current = top_next) {
			top_next = current->next;
			first = true;
			fprintf(out, "\ttype %u", current->type);
			do {
				uint_least16_t attributes = atomic_load_acquire(
					&current->attributes);
				if (!first) {
					fprintf(out, "\t");
				}
				first = false;
				fprintf(out,
					"\tserial = %lu, ttl = %u, "
					"trust = %u, attributes = %" PRIuLEAST16
					", "
					"resign = %u\n",
					(unsigned long)current->serial,
					current->rdh_ttl, current->trust,
					attributes,
					(current->resign << 1) |
						current->resign_lsb);
				current = current->down;
			} while (current != NULL);
		}
	} else {
		fprintf(out, "(empty)\n");
	}

	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_read);
}

static isc_result_t
createiterator(dns_db_t *db, unsigned int options,
	       dns_dbiterator_t **iteratorp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	rbtdb_dbiterator_t *rbtdbiter;

	REQUIRE(VALID_RBTDB(rbtdb));

	rbtdbiter = isc_mem_get(rbtdb->common.mctx, sizeof(*rbtdbiter));

	rbtdbiter->common.methods = &dbiterator_methods;
	rbtdbiter->common.db = NULL;
	dns_db_attach(db, &rbtdbiter->common.db);
	rbtdbiter->common.relative_names = ((options & DNS_DB_RELATIVENAMES) !=
					    0);
	rbtdbiter->common.magic = DNS_DBITERATOR_MAGIC;
	rbtdbiter->common.cleaning = false;
	rbtdbiter->paused = true;
	rbtdbiter->tree_locked = isc_rwlocktype_none;
	rbtdbiter->result = ISC_R_SUCCESS;
	dns_fixedname_init(&rbtdbiter->name);
	dns_fixedname_init(&rbtdbiter->origin);
	rbtdbiter->node = NULL;
	rbtdbiter->delcnt = 0;
	rbtdbiter->nsec3only = ((options & DNS_DB_NSEC3ONLY) != 0);
	rbtdbiter->nonsec3 = ((options & DNS_DB_NONSEC3) != 0);
	memset(rbtdbiter->deletions, 0, sizeof(rbtdbiter->deletions));
	dns_rbtnodechain_init(&rbtdbiter->chain);
	dns_rbtnodechain_init(&rbtdbiter->nsec3chain);
	if (rbtdbiter->nsec3only) {
		rbtdbiter->current = &rbtdbiter->nsec3chain;
	} else {
		rbtdbiter->current = &rbtdbiter->chain;
	}

	*iteratorp = (dns_dbiterator_t *)rbtdbiter;

	return (ISC_R_SUCCESS);
}

static isc_result_t
cache_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		   dns_rdatatype_t type, dns_rdatatype_t covers,
		   isc_stdtime_t now, dns_rdataset_t *rdataset,
		   dns_rdataset_t *sigrdataset) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rdatasetheader_t *header, *header_next, *found, *foundsig;
	rbtdb_rdatatype_t matchtype, sigmatchtype, negtype;
	isc_result_t result;
	nodelock_t *lock;
	isc_rwlocktype_t locktype;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(type != dns_rdatatype_any);

	UNUSED(version);

	result = ISC_R_SUCCESS;

	if (now == 0) {
		isc_stdtime_get(&now);
	}

	lock = &rbtdb->node_locks[rbtnode->locknum].lock;
	locktype = isc_rwlocktype_read;
	NODE_LOCK(lock, locktype);

	found = NULL;
	foundsig = NULL;
	matchtype = RBTDB_RDATATYPE_VALUE(type, covers);
	negtype = RBTDB_RDATATYPE_VALUE(0, type);
	if (covers == 0) {
		sigmatchtype = RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, type);
	} else {
		sigmatchtype = 0;
	}

	for (header = rbtnode->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (!ACTIVE(header, now)) {
			if ((header->rdh_ttl + rbtdb->serve_stale_ttl <
			     now - RBTDB_VIRTUAL) &&
			    (locktype == isc_rwlocktype_write ||
			     NODE_TRYUPGRADE(lock) == ISC_R_SUCCESS))
			{
				/*
				 * We update the node's status only when we
				 * can get write access.
				 */
				locktype = isc_rwlocktype_write;

				/*
				 * We don't check if refcurrent(rbtnode) == 0
				 * and try to free like we do in cache_find(),
				 * because refcurrent(rbtnode) must be
				 * non-zero.  This is so because 'node' is an
				 * argument to the function.
				 */
				mark_header_ancient(rbtdb, header);
			}
		} else if (EXISTS(header) && !ANCIENT(header)) {
			if (header->type == matchtype) {
				found = header;
			} else if (header->type == RBTDB_RDATATYPE_NCACHEANY ||
				   header->type == negtype) {
				found = header;
			} else if (header->type == sigmatchtype) {
				foundsig = header;
			}
		}
	}
	if (found != NULL) {
		bind_rdataset(rbtdb, rbtnode, found, now, locktype, rdataset);
		if (!NEGATIVE(found) && foundsig != NULL) {
			bind_rdataset(rbtdb, rbtnode, foundsig, now, locktype,
				      sigrdataset);
		}
	}

	NODE_UNLOCK(lock, locktype);

	if (found == NULL) {
		return (ISC_R_NOTFOUND);
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	}

	update_cachestats(rbtdb, result);

	return (result);
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     isc_stdtime_t now, dns_rdatasetiter_t **iteratorp) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	rbtdb_rdatasetiter_t *iterator;

	REQUIRE(VALID_RBTDB(rbtdb));

	iterator = isc_mem_get(rbtdb->common.mctx, sizeof(*iterator));

	if (now == 0) {
		isc_stdtime_get(&now);
	}

	iterator->common.magic = DNS_RDATASETITER_MAGIC;
	iterator->common.methods = &rdatasetiter_methods;
	iterator->common.db = db;
	iterator->common.node = node;
	iterator->common.version = (dns_dbversion_t *)rbtversion;
	iterator->common.now = now;

	isc_refcount_increment(&rbtnode->references);

	iterator->current = NULL;

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return (ISC_R_SUCCESS);
}

static bool
cname_and_other_data(dns_rbtnode_t *node, rbtdb_serial_t serial) {
	rdatasetheader_t *header, *header_next;
	bool cname, other_data;
	dns_rdatatype_t rdtype;

	/*
	 * The caller must hold the node lock.
	 */

	/*
	 * Look for CNAME and "other data" rdatasets active in our version.
	 */
	cname = false;
	other_data = false;
	for (header = node->data; header != NULL; header = header_next) {
		header_next = header->next;
		if (header->type == dns_rdatatype_cname) {
			/*
			 * Look for an active extant CNAME.
			 */
			do {
				if (header->serial <= serial && !IGNORE(header))
				{
					/*
					 * Is this a "this rdataset doesn't
					 * exist" record?
					 */
					if (NONEXISTENT(header)) {
						header = NULL;
					}
					break;
				} else {
					header = header->down;
				}
			} while (header != NULL);
			if (header != NULL) {
				cname = true;
			}
		} else {
			/*
			 * Look for active extant "other data".
			 *
			 * "Other data" is any rdataset whose type is not
			 * KEY, NSEC, SIG or RRSIG.
			 */
			rdtype = RBTDB_RDATATYPE_BASE(header->type);
			if (rdtype != dns_rdatatype_key &&
			    rdtype != dns_rdatatype_sig &&
			    rdtype != dns_rdatatype_nsec &&
			    rdtype != dns_rdatatype_rrsig)
			{
				/*
				 * Is it active and extant?
				 */
				do {
					if (header->serial <= serial &&
					    !IGNORE(header)) {
						/*
						 * Is this a "this rdataset
						 * doesn't exist" record?
						 */
						if (NONEXISTENT(header)) {
							header = NULL;
						}
						break;
					} else {
						header = header->down;
					}
				} while (header != NULL);
				if (header != NULL) {
					other_data = true;
				}
			}
		}
	}

	if (cname && other_data) {
		return (true);
	}

	return (false);
}

static isc_result_t
resign_insert(dns_rbtdb_t *rbtdb, int idx, rdatasetheader_t *newheader) {
	UNUSED(rbtdb);
	UNUSED(idx);
	UNUSED(newheader);

	INSIST(0);
}

/*
 * node write lock must be held.
 */
static void
resign_delete(dns_rbtdb_t *rbtdb, rbtdb_version_t *version,
	      rdatasetheader_t *header) {
	/*
	 * Remove the old header from the heap
	 */
	if (header != NULL && header->heap_index != 0) {
		isc_heap_delete(rbtdb->heaps[header->node->locknum],
				header->heap_index);
		header->heap_index = 0;
		if (version != NULL) {
			new_reference(rbtdb, header->node,
				      isc_rwlocktype_write);
			ISC_LIST_APPEND(version->resigned_list, header, link);
		}
	}
}

static inline uint64_t
recordsize(rdatasetheader_t *header, unsigned int namelen) {
	return (dns_rdataslab_rdatasize((unsigned char *)header,
					sizeof(*header)) +
		sizeof(dns_ttl_t) + sizeof(dns_rdatatype_t) +
		sizeof(dns_rdataclass_t) + namelen);
}

static void
update_recordsandxfrsize(bool add, rbtdb_version_t *rbtversion,
			 rdatasetheader_t *header, unsigned int namelen) {
	unsigned char *hdr = (unsigned char *)header;
	size_t hdrsize = sizeof(*header);

	RWLOCK(&rbtversion->rwlock, isc_rwlocktype_write);
	if (add) {
		rbtversion->records += dns_rdataslab_count(hdr, hdrsize);
		rbtversion->xfrsize += recordsize(header, namelen);
	} else {
		rbtversion->records -= dns_rdataslab_count(hdr, hdrsize);
		rbtversion->xfrsize -= recordsize(header, namelen);
	}
	RWUNLOCK(&rbtversion->rwlock, isc_rwlocktype_write);
}

/*
 * write lock on rbtnode must be held.
 */
static isc_result_t
add32(dns_rbtdb_t *rbtdb, dns_rbtnode_t *rbtnode, const dns_name_t *nodename,
      rbtdb_version_t *rbtversion, rdatasetheader_t *newheader,
      unsigned int options, bool loading, dns_rdataset_t *addedrdataset,
      isc_stdtime_t now) {
	rbtdb_changed_t *changed = NULL;
	rdatasetheader_t *topheader = NULL, *topheader_prev = NULL;
	rdatasetheader_t *header = NULL, *sigheader = NULL;
	isc_result_t result;
	bool header_nx;
	bool newheader_nx;
	dns_rdatatype_t rdtype, covers;
	rbtdb_rdatatype_t negtype, sigtype;
	dns_trust_t trust;
	int idx;

	/*
	 * Add an rdatasetheader_t to a node.
	 */

	/*
	 * Caller must be holding the node lock.
	 */

	if ((options & DNS_DBADD_FORCE) != 0) {
		trust = dns_trust_ultimate;
	} else {
		trust = newheader->trust;
	}

	if (rbtversion != NULL && !loading) {
		/*
		 * We always add a changed record, even if no changes end up
		 * being made to this node, because it's harmless and
		 * simplifies the code.
		 */
		changed = add_changed(rbtdb, rbtversion, rbtnode);
		if (changed == NULL) {
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			return (ISC_R_NOMEMORY);
		}
	}

	newheader_nx = NONEXISTENT(newheader) ? true : false;
	topheader_prev = NULL;
	sigheader = NULL;
	negtype = 0;
	if (rbtversion == NULL && !newheader_nx) {
		rdtype = RBTDB_RDATATYPE_BASE(newheader->type);
		covers = RBTDB_RDATATYPE_EXT(newheader->type);
		sigtype = RBTDB_RDATATYPE_VALUE(dns_rdatatype_rrsig, covers);
		if (NEGATIVE(newheader)) {
			/*
			 * We're adding a negative cache entry.
			 */
			if (covers == dns_rdatatype_any) {
				/*
				 * If we're adding an negative cache entry
				 * which covers all types (NXDOMAIN,
				 * NODATA(QTYPE=ANY)),
				 *
				 * We make all other data ancient so that the
				 * only rdataset that can be found at this
				 * node is the negative cache entry.
				 */
				for (topheader = rbtnode->data;
				     topheader != NULL;
				     topheader = topheader->next) {
					set_ttl(rbtdb, topheader, 0);
					mark_header_ancient(rbtdb, topheader);
				}
				goto find_header;
			}
			/*
			 * Otherwise look for any RRSIGs of the given
			 * type so they can be marked ancient later.
			 */
			for (topheader = rbtnode->data; topheader != NULL;
			     topheader = topheader->next) {
				if (topheader->type == sigtype) {
					sigheader = topheader;
				}
			}
			negtype = RBTDB_RDATATYPE_VALUE(covers, 0);
		} else {
			/*
			 * We're adding something that isn't a
			 * negative cache entry.  Look for an extant
			 * non-ancient NXDOMAIN/NODATA(QTYPE=ANY) negative
			 * cache entry.  If we're adding an RRSIG, also
			 * check for an extant non-ancient NODATA ncache
			 * entry which covers the same type as the RRSIG.
			 */
			for (topheader = rbtnode->data; topheader != NULL;
			     topheader = topheader->next) {
				if ((topheader->type ==
				     RBTDB_RDATATYPE_NCACHEANY) ||
				    (newheader->type == sigtype &&
				     topheader->type ==
					     RBTDB_RDATATYPE_VALUE(0, covers)))
				{
					break;
				}
			}
			if (topheader != NULL && EXISTS(topheader) &&
			    ACTIVE(topheader, now)) {
				/*
				 * Found one.
				 */
				if (trust < topheader->trust) {
					/*
					 * The NXDOMAIN/NODATA(QTYPE=ANY)
					 * is more trusted.
					 */
					free_rdataset(rbtdb, rbtdb->common.mctx,
						      newheader);
					if (addedrdataset != NULL) {
						bind_rdataset(
							rbtdb, rbtnode,
							topheader, now,
							isc_rwlocktype_write,
							addedrdataset);
					}
					return (DNS_R_UNCHANGED);
				}
				/*
				 * The new rdataset is better.  Expire the
				 * ncache entry.
				 */
				set_ttl(rbtdb, topheader, 0);
				mark_header_ancient(rbtdb, topheader);
				topheader = NULL;
				goto find_header;
			}
			negtype = RBTDB_RDATATYPE_VALUE(0, rdtype);
		}
	}

	for (topheader = rbtnode->data; topheader != NULL;
	     topheader = topheader->next) {
		if (topheader->type == newheader->type ||
		    topheader->type == negtype) {
			break;
		}
		topheader_prev = topheader;
	}

find_header:
	/*
	 * If header isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	header = topheader;
	while (header != NULL && IGNORE(header)) {
		header = header->down;
	}
	if (header != NULL) {
		header_nx = NONEXISTENT(header) ? true : false;

		/*
		 * Deleting an already non-existent rdataset has no effect.
		 */
		if (header_nx && newheader_nx) {
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			return (DNS_R_UNCHANGED);
		}

		/*
		 * Trying to add an rdataset with lower trust to a cache
		 * DB has no effect, provided that the cache data isn't
		 * stale. If the cache data is stale, new lower trust
		 * data will supersede it below. Unclear what the best
		 * policy is here.
		 */
		if (rbtversion == NULL && trust < header->trust &&
		    (ACTIVE(header, now) || header_nx))
		{
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			if (addedrdataset != NULL) {
				bind_rdataset(rbtdb, rbtnode, header, now,
					      isc_rwlocktype_write,
					      addedrdataset);
			}
			return (DNS_R_UNCHANGED);
		}

		/*
		 * Don't replace existing NS, A and AAAA RRsets in the
		 * cache if they are already exist. This prevents named
		 * being locked to old servers. Don't lower trust of
		 * existing record if the update is forced. Nothing
		 * special to be done w.r.t stale data; it gets replaced
		 * normally further down.
		 */
		if (ACTIVE(header, now) && header->type == dns_rdatatype_ns &&
		    !header_nx && !newheader_nx &&
		    header->trust >= newheader->trust &&
		    dns_rdataslab_equalx((unsigned char *)header,
					 (unsigned char *)newheader,
					 (unsigned int)(sizeof(*newheader)),
					 rbtdb->common.rdclass,
					 (dns_rdatatype_t)header->type))
		{
			/*
			 * Honour the new ttl if it is less than the
			 * older one.
			 */
			if (header->rdh_ttl > newheader->rdh_ttl) {
				set_ttl(rbtdb, header, newheader->rdh_ttl);
			}
			if (header->noqname == NULL &&
			    newheader->noqname != NULL) {
				header->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (header->closest == NULL &&
			    newheader->closest != NULL) {
				header->closest = newheader->closest;
				newheader->closest = NULL;
			}
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			if (addedrdataset != NULL) {
				bind_rdataset(rbtdb, rbtnode, header, now,
					      isc_rwlocktype_write,
					      addedrdataset);
			}
			return (ISC_R_SUCCESS);
		}
		/*
		 * If we have will be replacing a NS RRset force its TTL
		 * to be no more than the current NS RRset's TTL.  This
		 * ensures the delegations that are withdrawn are honoured.
		 */
		if (ACTIVE(header, now) && header->type == dns_rdatatype_ns &&
		    !header_nx && !newheader_nx &&
		    header->trust <= newheader->trust)
		{
			if (newheader->rdh_ttl > header->rdh_ttl) {
				newheader->rdh_ttl = header->rdh_ttl;
			}
		}
		if (ACTIVE(header, now) &&
		    (options & DNS_DBADD_PREFETCH) == 0 &&
		    (header->type == dns_rdatatype_a ||
		     header->type == dns_rdatatype_aaaa ||
		     header->type == dns_rdatatype_ds ||
		     header->type == RBTDB_RDATATYPE_SIGDS) &&
		    !header_nx && !newheader_nx &&
		    header->trust >= newheader->trust &&
		    dns_rdataslab_equal((unsigned char *)header,
					(unsigned char *)newheader,
					(unsigned int)(sizeof(*newheader))))
		{
			/*
			 * Honour the new ttl if it is less than the
			 * older one.
			 */
			if (header->rdh_ttl > newheader->rdh_ttl) {
				set_ttl(rbtdb, header, newheader->rdh_ttl);
			}
			if (header->noqname == NULL &&
			    newheader->noqname != NULL) {
				header->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (header->closest == NULL &&
			    newheader->closest != NULL) {
				header->closest = newheader->closest;
				newheader->closest = NULL;
			}
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			if (addedrdataset != NULL) {
				bind_rdataset(rbtdb, rbtnode, header, now,
					      isc_rwlocktype_write,
					      addedrdataset);
			}
			return (ISC_R_SUCCESS);
		}
		INSIST(rbtversion == NULL ||
		       rbtversion->serial >= topheader->serial);
		if (loading) {
			newheader->down = NULL;
			idx = newheader->node->locknum;

			if (ZEROTTL(newheader)) {
				ISC_LIST_APPEND(rbtdb->rdatasets[idx],
						newheader, link);
			} else {
				ISC_LIST_PREPEND(rbtdb->rdatasets[idx],
						 newheader, link);
			}
			INSIST(rbtdb->heaps != NULL);
			result = isc_heap_insert(rbtdb->heaps[idx], newheader);
			if (result != ISC_R_SUCCESS) {
				free_rdataset(rbtdb, rbtdb->common.mctx,
					      newheader);
				return (result);
			}

			/*
			 * There are no other references to 'header' when
			 * loading, so we MAY clean up 'header' now.
			 * Since we don't generate changed records when
			 * loading, we MUST clean up 'header' now.
			 */
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				rbtnode->data = newheader;
			}
			newheader->next = topheader->next;
			if (rbtversion != NULL && !header_nx) {
				update_recordsandxfrsize(false, rbtversion,
							 header,
							 nodename->length);
			}
			free_rdataset(rbtdb, rbtdb->common.mctx, header);
		} else {
			idx = newheader->node->locknum;

			INSIST(rbtdb->heaps != NULL);
			result = isc_heap_insert(rbtdb->heaps[idx], newheader);
			if (result != ISC_R_SUCCESS) {
				free_rdataset(rbtdb, rbtdb->common.mctx,
					      newheader);
				return (result);
			}
			if (ZEROTTL(newheader)) {
				ISC_LIST_APPEND(rbtdb->rdatasets[idx],
						newheader, link);
			} else {
				ISC_LIST_PREPEND(rbtdb->rdatasets[idx],
						 newheader, link);
			}

			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				rbtnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			rbtnode->dirty = 1;
			if (changed != NULL) {
				changed->dirty = true;
			}
			if (rbtversion == NULL) {
				set_ttl(rbtdb, header, 0);
				mark_header_ancient(rbtdb, header);
				if (sigheader != NULL) {
					set_ttl(rbtdb, sigheader, 0);
					mark_header_ancient(rbtdb, sigheader);
				}
			}
			if (rbtversion != NULL && !header_nx) {
				update_recordsandxfrsize(false, rbtversion,
							 header,
							 nodename->length);
			}
		}
	} else {
		/*
		 * No non-IGNORED rdatasets of the given type exist at
		 * this node.
		 */

		/*
		 * If we're trying to delete the type, don't bother.
		 */
		if (newheader_nx) {
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			return (DNS_R_UNCHANGED);
		}

		idx = newheader->node->locknum;

		result = isc_heap_insert(rbtdb->heaps[idx], newheader);
		if (result != ISC_R_SUCCESS) {
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			return (result);
		}
		if (ZEROTTL(newheader)) {
			ISC_LIST_APPEND(rbtdb->rdatasets[idx], newheader, link);
		} else {
			ISC_LIST_PREPEND(rbtdb->rdatasets[idx], newheader,
					 link);
		}

		if (topheader != NULL) {
			/*
			 * We have an list of rdatasets of the given type,
			 * but they're all marked IGNORE.  We simply insert
			 * the new rdataset at the head of the list.
			 *
			 * Ignored rdatasets cannot occur during loading, so
			 * we INSIST on it.
			 */
			INSIST(!loading);
			INSIST(rbtversion == NULL ||
			       rbtversion->serial >= topheader->serial);
			if (topheader_prev != NULL) {
				topheader_prev->next = newheader;
			} else {
				rbtnode->data = newheader;
			}
			newheader->next = topheader->next;
			newheader->down = topheader;
			topheader->next = newheader;
			rbtnode->dirty = 1;
			if (changed != NULL) {
				changed->dirty = true;
			}
		} else {
			/*
			 * No rdatasets of the given type exist at the node.
			 */
			newheader->next = rbtnode->data;
			newheader->down = NULL;
			rbtnode->data = newheader;
		}
	}

	if (rbtversion != NULL && !newheader_nx) {
		update_recordsandxfrsize(true, rbtversion, newheader,
					 nodename->length);
	}

	/*
	 * Check if the node now contains CNAME and other data.
	 */
	if (rbtversion != NULL &&
	    cname_and_other_data(rbtnode, rbtversion->serial)) {
		return (DNS_R_CNAMEANDOTHER);
	}

	if (addedrdataset != NULL) {
		bind_rdataset(rbtdb, rbtnode, newheader, now,
			      isc_rwlocktype_write, addedrdataset);
	}

	return (ISC_R_SUCCESS);
}

static inline bool
delegating_type(rbtdb_rdatatype_t type) {
	return (type == dns_rdatatype_dname);
}

static inline isc_result_t
addnoqname(dns_rbtdb_t *rbtdb, rdatasetheader_t *newheader,
	   dns_rdataset_t *rdataset) {
	struct noqname *noqname;
	isc_mem_t *mctx = rbtdb->common.mctx;
	dns_name_t name;
	dns_rdataset_t neg, negsig;
	isc_result_t result;
	isc_region_t r;

	dns_name_init(&name, NULL);
	dns_rdataset_init(&neg);
	dns_rdataset_init(&negsig);

	result = dns_rdataset_getnoqname(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	noqname = isc_mem_get(mctx, sizeof(*noqname));
	dns_name_init(&noqname->name, NULL);
	noqname->neg = NULL;
	noqname->negsig = NULL;
	noqname->type = neg.type;
	dns_name_dup(&name, mctx, &noqname->name);
	result = dns_rdataslab_fromrdataset(&neg, mctx, &r, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	noqname->neg = r.base;
	result = dns_rdataslab_fromrdataset(&negsig, mctx, &r, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	noqname->negsig = r.base;
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	newheader->noqname = noqname;
	return (ISC_R_SUCCESS);

cleanup:
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	free_noqname(mctx, &noqname);
	return (result);
}

static inline isc_result_t
addclosest(dns_rbtdb_t *rbtdb, rdatasetheader_t *newheader,
	   dns_rdataset_t *rdataset) {
	struct noqname *closest;
	isc_mem_t *mctx = rbtdb->common.mctx;
	dns_name_t name;
	dns_rdataset_t neg, negsig;
	isc_result_t result;
	isc_region_t r;

	dns_name_init(&name, NULL);
	dns_rdataset_init(&neg);
	dns_rdataset_init(&negsig);

	result = dns_rdataset_getclosest(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	closest = isc_mem_get(mctx, sizeof(*closest));
	dns_name_init(&closest->name, NULL);
	closest->neg = NULL;
	closest->negsig = NULL;
	closest->type = neg.type;
	dns_name_dup(&name, mctx, &closest->name);
	result = dns_rdataslab_fromrdataset(&neg, mctx, &r, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	closest->neg = r.base;
	result = dns_rdataslab_fromrdataset(&negsig, mctx, &r, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	closest->negsig = r.base;
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	newheader->closest = closest;
	return (ISC_R_SUCCESS);

cleanup:
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	free_noqname(mctx, &closest);
	return (result);
}

static isc_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    isc_stdtime_t now, dns_rdataset_t *rdataset, unsigned int options,
	    dns_rdataset_t *addedrdataset) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	isc_region_t region;
	rdatasetheader_t *newheader;
	rdatasetheader_t *header;
	isc_result_t result;
	bool delegating;
	bool newnsec;
	bool tree_locked = false;
	bool cache_is_overmem = false;
	dns_fixedname_t fixed;
	dns_name_t *name;

	REQUIRE(VALID_RBTDB(rbtdb));
	INSIST(rbtversion == NULL || rbtversion->rbtdb == rbtdb);

	if (rbtversion == NULL) {
		if (now == 0) {
			isc_stdtime_get(&now);
		}
	} else {
		now = 0;
	}

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region, sizeof(rdatasetheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	name = dns_fixedname_initname(&fixed);
	nodefullname(db, node, name);
	dns_rdataset_getownercase(rdataset, name);

	newheader = (rdatasetheader_t *)region.base;
	init_rdataset(rbtdb, newheader);
	setownercase(newheader, name);
	set_ttl(rbtdb, newheader, rdataset->ttl + now);
	newheader->type = RBTDB_RDATATYPE_VALUE(rdataset->type,
						rdataset->covers);
	atomic_init(&newheader->attributes, 0);
	if (rdataset->ttl == 0U) {
		RDATASET_ATTR_SET(newheader, RDATASET_ATTR_ZEROTTL);
	}
	newheader->noqname = NULL;
	newheader->closest = NULL;
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	newheader->trust = rdataset->trust;
	newheader->last_used = now;
	newheader->node = rbtnode;
	if (rbtversion != NULL) {
		newheader->serial = rbtversion->serial;
		now = 0;

		if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
			RDATASET_ATTR_SET(newheader, RDATASET_ATTR_RESIGN);
			newheader->resign =
				(isc_stdtime_t)(dns_time64_from32(
							rdataset->resign) >>
						1);
			newheader->resign_lsb = rdataset->resign & 0x1;
		} else {
			newheader->resign = 0;
			newheader->resign_lsb = 0;
		}
	} else {
		newheader->serial = 1;
		newheader->resign = 0;
		newheader->resign_lsb = 0;
		if ((rdataset->attributes & DNS_RDATASETATTR_PREFETCH) != 0) {
			RDATASET_ATTR_SET(newheader, RDATASET_ATTR_PREFETCH);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0) {
			RDATASET_ATTR_SET(newheader, RDATASET_ATTR_NEGATIVE);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_NXDOMAIN) != 0) {
			RDATASET_ATTR_SET(newheader, RDATASET_ATTR_NXDOMAIN);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_OPTOUT) != 0) {
			RDATASET_ATTR_SET(newheader, RDATASET_ATTR_OPTOUT);
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_NOQNAME) != 0) {
			result = addnoqname(rbtdb, newheader, rdataset);
			if (result != ISC_R_SUCCESS) {
				free_rdataset(rbtdb, rbtdb->common.mctx,
					      newheader);
				return (result);
			}
		}
		if ((rdataset->attributes & DNS_RDATASETATTR_CLOSEST) != 0) {
			result = addclosest(rbtdb, newheader, rdataset);
			if (result != ISC_R_SUCCESS) {
				free_rdataset(rbtdb, rbtdb->common.mctx,
					      newheader);
				return (result);
			}
		}
	}

	/*
	 * If we're adding a delegation type (e.g. NS or DNAME for a zone,
	 * just DNAME for the cache), then we need to set the callback bit
	 * on the node.
	 */
	if (delegating_type(rdataset->type)) {
		delegating = true;
	} else {
		delegating = false;
	}

	/*
	 * Add to the auxiliary NSEC tree if we're adding an NSEC record.
	 */
	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	if (rbtnode->nsec != DNS_RBT_NSEC_HAS_NSEC &&
	    rdataset->type == dns_rdatatype_nsec)
	{
		newnsec = true;
	} else {
		newnsec = false;
	}
	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);

	/*
	 * If we're adding a delegation type, adding to the auxiliary NSEC
	 * tree, or the DB is a cache in an overmem state, hold an
	 * exclusive lock on the tree.  In the latter case the lock does
	 * not necessarily have to be acquired but it will help purge
	 * ancient entries more effectively.
	 */
	if (isc_mem_isovermem(rbtdb->common.mctx)) {
		cache_is_overmem = true;
	}
	if (delegating || newnsec || cache_is_overmem) {
		tree_locked = true;
		RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
	}

	if (cache_is_overmem) {
		overmem_purge(rbtdb, rbtnode->locknum, now, tree_locked);
	}

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);

	if (rbtdb->rrsetstats != NULL) {
		RDATASET_ATTR_SET(newheader, RDATASET_ATTR_STATCOUNT);
		update_rrsetstats(rbtdb, newheader->type,
				  atomic_load_acquire(&newheader->attributes),
				  true);
	}

	if (tree_locked) {
		cleanup_dead_nodes(rbtdb, rbtnode->locknum);
	}

	header = isc_heap_element(rbtdb->heaps[rbtnode->locknum], 1);
	if (header != NULL &&
	    header->rdh_ttl + rbtdb->serve_stale_ttl < now - RBTDB_VIRTUAL)
	{
		expire_header(rbtdb, header, tree_locked, expire_ttl);
	}

	/*
	 * If we've been holding a write lock on the tree just for
	 * cleaning, we can release it now.  However, we still need the
	 * node lock.
	 */
	if (tree_locked && !delegating && !newnsec) {
		RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
		tree_locked = false;
	}

	result = ISC_R_SUCCESS;
	if (newnsec) {
		dns_rbtnode_t *nsecnode;

		nsecnode = NULL;
		result = dns_rbt_addnode(rbtdb->nsec, name, &nsecnode);
		if (result == ISC_R_SUCCESS) {
			nsecnode->nsec = DNS_RBT_NSEC_NSEC;
			rbtnode->nsec = DNS_RBT_NSEC_HAS_NSEC;
		} else if (result == ISC_R_EXISTS) {
			rbtnode->nsec = DNS_RBT_NSEC_HAS_NSEC;
			result = ISC_R_SUCCESS;
		}
	}

	if (result == ISC_R_SUCCESS) {
		result = add32(rbtdb, rbtnode, name, rbtversion, newheader,
			       options, false, addedrdataset, now);
	}
	if (result == ISC_R_SUCCESS && delegating) {
		rbtnode->find_callback = 1;
	}

	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);

	if (tree_locked) {
		RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
	}

	return (result);
}

static isc_result_t
subtractrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 dns_rdataset_t *rdataset, unsigned int options,
		 dns_rdataset_t *newrdataset) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	dns_fixedname_t fname;
	dns_name_t *nodename = dns_fixedname_initname(&fname);
	rdatasetheader_t *topheader, *topheader_prev, *header, *newheader;
	unsigned char *subresult;
	isc_region_t region;
	isc_result_t result;
	rbtdb_changed_t *changed;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(rbtversion != NULL && rbtversion->rbtdb == rbtdb);

	nodefullname(db, node, nodename);

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region, sizeof(rdatasetheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	newheader = (rdatasetheader_t *)region.base;
	init_rdataset(rbtdb, newheader);
	set_ttl(rbtdb, newheader, rdataset->ttl);
	newheader->type = RBTDB_RDATATYPE_VALUE(rdataset->type,
						rdataset->covers);
	atomic_init(&newheader->attributes, 0);
	newheader->serial = rbtversion->serial;
	newheader->trust = 0;
	newheader->noqname = NULL;
	newheader->closest = NULL;
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	newheader->last_used = 0;
	newheader->node = rbtnode;
	if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
		RDATASET_ATTR_SET(newheader, RDATASET_ATTR_RESIGN);
		newheader->resign =
			(isc_stdtime_t)(dns_time64_from32(rdataset->resign) >>
					1);
		newheader->resign_lsb = rdataset->resign & 0x1;
	} else {
		newheader->resign = 0;
		newheader->resign_lsb = 0;
	}

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);

	changed = add_changed(rbtdb, rbtversion, rbtnode);
	if (changed == NULL) {
		free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
		NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
			    isc_rwlocktype_write);
		return (ISC_R_NOMEMORY);
	}

	topheader_prev = NULL;
	for (topheader = rbtnode->data; topheader != NULL;
	     topheader = topheader->next) {
		if (topheader->type == newheader->type) {
			break;
		}
		topheader_prev = topheader;
	}
	/*
	 * If header isn't NULL, we've found the right type.  There may be
	 * IGNORE rdatasets between the top of the chain and the first real
	 * data.  We skip over them.
	 */
	header = topheader;
	while (header != NULL && IGNORE(header)) {
		header = header->down;
	}
	if (header != NULL && EXISTS(header)) {
		unsigned int flags = 0;
		subresult = NULL;
		result = ISC_R_SUCCESS;
		if ((options & DNS_DBSUB_EXACT) != 0) {
			flags |= DNS_RDATASLAB_EXACT;
			if (newheader->rdh_ttl != header->rdh_ttl) {
				result = DNS_R_NOTEXACT;
			}
		}
		if (result == ISC_R_SUCCESS) {
			result = dns_rdataslab_subtract(
				(unsigned char *)header,
				(unsigned char *)newheader,
				(unsigned int)(sizeof(*newheader)),
				rbtdb->common.mctx, rbtdb->common.rdclass,
				(dns_rdatatype_t)header->type, flags,
				&subresult);
		}
		if (result == ISC_R_SUCCESS) {
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			newheader = (rdatasetheader_t *)subresult;
			init_rdataset(rbtdb, newheader);
			update_newheader(newheader, header);
			if (RESIGN(header)) {
				RDATASET_ATTR_SET(newheader,
						  RDATASET_ATTR_RESIGN);
				newheader->resign = header->resign;
				newheader->resign_lsb = header->resign_lsb;
				result = resign_insert(rbtdb, rbtnode->locknum,
						       newheader);
				if (result != ISC_R_SUCCESS) {
					free_rdataset(rbtdb, rbtdb->common.mctx,
						      newheader);
					goto unlock;
				}
			}
			/*
			 * We have to set the serial since the rdataslab
			 * subtraction routine copies the reserved portion of
			 * header, not newheader.
			 */
			newheader->serial = rbtversion->serial;
			/*
			 * XXXJT: dns_rdataslab_subtract() copied the pointers
			 * to additional info.  We need to clear these fields
			 * to avoid having duplicated references.
			 */
			update_recordsandxfrsize(true, rbtversion, newheader,
						 nodename->length);
		} else if (result == DNS_R_NXRRSET) {
			/*
			 * This subtraction would remove all of the rdata;
			 * add a nonexistent header instead.
			 */
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			newheader = new_rdataset(rbtdb, rbtdb->common.mctx);
			if (newheader == NULL) {
				result = ISC_R_NOMEMORY;
				goto unlock;
			}
			init_rdataset(rbtdb, newheader);
			set_ttl(rbtdb, newheader, 0);
			newheader->type = topheader->type;
			atomic_init(&newheader->attributes,
				    RDATASET_ATTR_NONEXISTENT);
			newheader->trust = 0;
			newheader->serial = rbtversion->serial;
			newheader->noqname = NULL;
			newheader->closest = NULL;
			atomic_init(&newheader->count, 0);
			newheader->node = rbtnode;
			newheader->resign = 0;
			newheader->resign_lsb = 0;
			newheader->last_used = 0;
		} else {
			free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
			goto unlock;
		}

		/*
		 * If we're here, we want to link newheader in front of
		 * topheader.
		 */
		INSIST(rbtversion->serial >= topheader->serial);
		update_recordsandxfrsize(false, rbtversion, header,
					 nodename->length);
		if (topheader_prev != NULL) {
			topheader_prev->next = newheader;
		} else {
			rbtnode->data = newheader;
		}
		newheader->next = topheader->next;
		newheader->down = topheader;
		topheader->next = newheader;
		rbtnode->dirty = 1;
		changed->dirty = true;
		resign_delete(rbtdb, rbtversion, header);
	} else {
		/*
		 * The rdataset doesn't exist, so we don't need to do anything
		 * to satisfy the deletion request.
		 */
		free_rdataset(rbtdb, rbtdb->common.mctx, newheader);
		if ((options & DNS_DBSUB_EXACT) != 0) {
			result = DNS_R_NOTEXACT;
		} else {
			result = DNS_R_UNCHANGED;
		}
	}

	if (result == ISC_R_SUCCESS && newrdataset != NULL) {
		bind_rdataset(rbtdb, rbtnode, newheader, 0,
			      isc_rwlocktype_write, newrdataset);
	}

	if (result == DNS_R_NXRRSET && newrdataset != NULL &&
	    (options & DNS_DBSUB_WANTOLD) != 0)
	{
		bind_rdataset(rbtdb, rbtnode, header, 0, isc_rwlocktype_write,
			      newrdataset);
	}

unlock:
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);

	return (result);
}

static isc_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type, dns_rdatatype_t covers) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	rbtdb_version_t *rbtversion = version;
	dns_fixedname_t fname;
	dns_name_t *nodename = dns_fixedname_initname(&fname);
	isc_result_t result;
	rdatasetheader_t *newheader;

	REQUIRE(VALID_RBTDB(rbtdb));
	INSIST(rbtversion == NULL || rbtversion->rbtdb == rbtdb);

	if (type == dns_rdatatype_any) {
		return (ISC_R_NOTIMPLEMENTED);
	}
	if (type == dns_rdatatype_rrsig && covers == 0) {
		return (ISC_R_NOTIMPLEMENTED);
	}

	newheader = new_rdataset(rbtdb, rbtdb->common.mctx);
	if (newheader == NULL) {
		return (ISC_R_NOMEMORY);
	}
	init_rdataset(rbtdb, newheader);
	set_ttl(rbtdb, newheader, 0);
	newheader->type = RBTDB_RDATATYPE_VALUE(type, covers);
	atomic_init(&newheader->attributes, RDATASET_ATTR_NONEXISTENT);
	newheader->trust = 0;
	newheader->noqname = NULL;
	newheader->closest = NULL;
	if (rbtversion != NULL) {
		newheader->serial = rbtversion->serial;
	} else {
		newheader->serial = 0;
	}
	atomic_init(&newheader->count, 0);
	newheader->last_used = 0;
	newheader->node = rbtnode;

	nodefullname(db, node, nodename);

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);
	result = add32(rbtdb, rbtnode, nodename, rbtversion, newheader,
		       DNS_DBADD_FORCE, false, NULL, 0);
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);

	return (result);
}

/*
 * load a non-NSEC3 node in the main tree and optionally to the auxiliary NSEC
 */
static isc_result_t
loadnode(dns_rbtdb_t *rbtdb, const dns_name_t *name, dns_rbtnode_t **nodep,
	 bool hasnsec) {
	isc_result_t noderesult, nsecresult, tmpresult;
	dns_rbtnode_t *nsecnode = NULL, *node = NULL;

	noderesult = dns_rbt_addnode(rbtdb->tree, name, &node);
	if (!hasnsec) {
		goto done;
	}
	if (noderesult == ISC_R_EXISTS) {
		/*
		 * Add a node to the auxiliary NSEC tree for an old node
		 * just now getting an NSEC record.
		 */
		if (node->nsec == DNS_RBT_NSEC_HAS_NSEC) {
			goto done;
		}
	} else if (noderesult != ISC_R_SUCCESS) {
		goto done;
	}

	/*
	 * Build the auxiliary tree for NSECs as we go.
	 * This tree speeds searches for closest NSECs that would otherwise
	 * need to examine many irrelevant nodes in large TLDs.
	 *
	 * Add nodes to the auxiliary tree after corresponding nodes have
	 * been added to the main tree.
	 */
	nsecresult = dns_rbt_addnode(rbtdb->nsec, name, &nsecnode);
	if (nsecresult == ISC_R_SUCCESS) {
		nsecnode->nsec = DNS_RBT_NSEC_NSEC;
		node->nsec = DNS_RBT_NSEC_HAS_NSEC;
		goto done;
	}

	if (nsecresult == ISC_R_EXISTS) {
#if 1 /* 0 */
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
			      "addnode: NSEC node already exists");
#endif /* if 1 */
		node->nsec = DNS_RBT_NSEC_HAS_NSEC;
		goto done;
	}

	if (noderesult == ISC_R_SUCCESS) {
		/*
		 * Remove the node we just added above.
		 */
		tmpresult = dns_rbt_deletenode(rbtdb->tree, node, false);
		if (tmpresult != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_CACHE, ISC_LOG_WARNING,
				      "loading_addrdataset: "
				      "dns_rbt_deletenode: %s after "
				      "dns_rbt_addnode(NSEC): %s",
				      isc_result_totext(tmpresult),
				      isc_result_totext(noderesult));
		}
	}

	/*
	 * Set the error condition to be returned.
	 */
	noderesult = nsecresult;

done:
	if (noderesult == ISC_R_SUCCESS || noderesult == ISC_R_EXISTS) {
		*nodep = node;
	}

	return (noderesult);
}

static isc_result_t
loading_addrdataset(void *arg, const dns_name_t *name,
		    dns_rdataset_t *rdataset) {
	rbtdb_load_t *loadctx = arg;
	dns_rbtdb_t *rbtdb = loadctx->rbtdb;
	dns_rbtnode_t *node;
	isc_result_t result;
	isc_region_t region;
	rdatasetheader_t *newheader;

	REQUIRE(rdataset->rdclass == rbtdb->common.rdclass);

	if (rdataset->type != dns_rdatatype_nsec3 &&
	    rdataset->covers != dns_rdatatype_nsec3)
	{
		add_empty_wildcards(rbtdb, name);
	}

	if (dns_name_iswildcard(name)) {
		/*
		 * NS record owners cannot legally be wild cards.
		 */
		if (rdataset->type == dns_rdatatype_ns) {
			return (DNS_R_INVALIDNS);
		}
		/*
		 * NSEC3 record owners cannot legally be wild cards.
		 */
		if (rdataset->type == dns_rdatatype_nsec3) {
			return (DNS_R_INVALIDNSEC3);
		}
		result = add_wildcard_magic(rbtdb, name);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	}

	node = NULL;
	if (rdataset->type == dns_rdatatype_nsec3 ||
	    rdataset->covers == dns_rdatatype_nsec3)
	{
		result = dns_rbt_addnode(rbtdb->nsec3, name, &node);
		if (result == ISC_R_SUCCESS) {
			node->nsec = DNS_RBT_NSEC_NSEC3;
		}
	} else if (rdataset->type == dns_rdatatype_nsec) {
		result = loadnode(rbtdb, name, &node, true);
	} else {
		result = loadnode(rbtdb, name, &node, false);
	}
	if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
		return (result);
	}
	if (result == ISC_R_SUCCESS) {
		node->locknum = node->hashval % rbtdb->node_lock_count;
	}

	result = dns_rdataslab_fromrdataset(rdataset, rbtdb->common.mctx,
					    &region, sizeof(rdatasetheader_t));
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	newheader = (rdatasetheader_t *)region.base;
	init_rdataset(rbtdb, newheader);
	set_ttl(rbtdb, newheader, rdataset->ttl + loadctx->now); /* XXX overflow
								  * check */
	newheader->type = RBTDB_RDATATYPE_VALUE(rdataset->type,
						rdataset->covers);
	atomic_init(&newheader->attributes, 0);
	newheader->trust = rdataset->trust;
	newheader->serial = 1;
	newheader->noqname = NULL;
	newheader->closest = NULL;
	atomic_init(&newheader->count,
		    atomic_fetch_add_relaxed(&init_count, 1));
	newheader->last_used = 0;
	newheader->node = node;
	setownercase(newheader, name);

	if ((rdataset->attributes & DNS_RDATASETATTR_RESIGN) != 0) {
		RDATASET_ATTR_SET(newheader, RDATASET_ATTR_RESIGN);
		newheader->resign =
			(isc_stdtime_t)(dns_time64_from32(rdataset->resign) >>
					1);
		newheader->resign_lsb = rdataset->resign & 0x1;
	} else {
		newheader->resign = 0;
		newheader->resign_lsb = 0;
	}

	NODE_LOCK(&rbtdb->node_locks[node->locknum].lock, isc_rwlocktype_write);
	result = add32(rbtdb, node, name, rbtdb->current_version, newheader,
		       DNS_DBADD_MERGE, true, NULL, 0);
	NODE_UNLOCK(&rbtdb->node_locks[node->locknum].lock,
		    isc_rwlocktype_write);

	if (result == ISC_R_SUCCESS && delegating_type(rdataset->type)) {
		node->find_callback = 1;
	} else if (result == DNS_R_UNCHANGED) {
		result = ISC_R_SUCCESS;
	}

	return (result);
}

static isc_result_t
beginload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	rbtdb_load_t *loadctx;
	dns_rbtdb_t *rbtdb;
	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(DNS_CALLBACK_VALID(callbacks));
	REQUIRE(VALID_RBTDB(rbtdb));

	loadctx = isc_mem_get(rbtdb->common.mctx, sizeof(*loadctx));

	loadctx->rbtdb = rbtdb;
	isc_stdtime_get(&loadctx->now);

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);

	REQUIRE((rbtdb->attributes &
		 (RBTDB_ATTR_LOADED | RBTDB_ATTR_LOADING)) == 0);
	rbtdb->attributes |= RBTDB_ATTR_LOADING;

	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);

	callbacks->add = loading_addrdataset;
	callbacks->add_private = loadctx;

	return (ISC_R_SUCCESS);
}

static isc_result_t
endload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	rbtdb_load_t *loadctx;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(DNS_CALLBACK_VALID(callbacks));
	loadctx = callbacks->add_private;
	REQUIRE(loadctx != NULL);
	REQUIRE(loadctx->rbtdb == rbtdb);

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);

	REQUIRE((rbtdb->attributes & RBTDB_ATTR_LOADING) != 0);
	REQUIRE((rbtdb->attributes & RBTDB_ATTR_LOADED) == 0);

	rbtdb->attributes &= ~RBTDB_ATTR_LOADING;
	rbtdb->attributes |= RBTDB_ATTR_LOADED;

	/*
	 * If there's a KEY rdataset at the zone origin containing a
	 * zone key, we consider the zone secure.
	 */
	if (rbtdb->origin_node != NULL) {
		dns_dbversion_t *version = rbtdb->current_version;
		RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);
		iszonesecure(db, version, rbtdb->origin_node);
	} else {
		RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);
	}

	callbacks->add = NULL;
	callbacks->add_private = NULL;

	isc_mem_put(rbtdb->common.mctx, loadctx, sizeof(*loadctx));

	return (ISC_R_SUCCESS);
}

static isc_result_t
dump(dns_db_t *db, dns_dbversion_t *version, const char *filename,
     dns_masterformat_t masterformat) {
	dns_rbtdb_t *rbtdb;
	rbtdb_version_t *rbtversion = version;

	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));
	INSIST(rbtversion == NULL || rbtversion->rbtdb == rbtdb);

	return (dns_master_dump(rbtdb->common.mctx, db, version,
				&dns_master_style_default, filename,
				masterformat, NULL));
}

static void
delete_callback(void *data, void *arg) {
	dns_rbtdb_t *rbtdb = arg;
	rdatasetheader_t *current, *next;
	unsigned int locknum;

	current = data;
	locknum = current->node->locknum;
	NODE_LOCK(&rbtdb->node_locks[locknum].lock, isc_rwlocktype_write);
	while (current != NULL) {
		next = current->next;
		free_rdataset(rbtdb, rbtdb->common.mctx, current);
		current = next;
	}
	NODE_UNLOCK(&rbtdb->node_locks[locknum].lock, isc_rwlocktype_write);
}

static bool
issecure(dns_db_t *db) {
	dns_rbtdb_t *rbtdb;
	bool secure;

	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_read);
	secure = (rbtdb->current_version->secure == dns_db_secure);
	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_read);

	return (secure);
}

static bool
isdnssec(dns_db_t *db) {
	dns_rbtdb_t *rbtdb;
	bool dnssec;

	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_read);
	dnssec = (rbtdb->current_version->secure != dns_db_insecure);
	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_read);

	return (dnssec);
}

static unsigned int
nodecount(dns_db_t *db) {
	dns_rbtdb_t *rbtdb;
	unsigned int count;

	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	count = dns_rbt_nodecount(rbtdb->tree);
	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);

	return (count);
}

static size_t
hashsize(dns_db_t *db) {
	dns_rbtdb_t *rbtdb;
	size_t size;

	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	size = dns_rbt_hashsize(rbtdb->tree);
	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);

	return (size);
}

static void
settask(dns_db_t *db, isc_task_t *task) {
	dns_rbtdb_t *rbtdb;

	rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	RBTDB_LOCK(&rbtdb->lock, isc_rwlocktype_write);
	if (rbtdb->task != NULL) {
		isc_task_detach(&rbtdb->task);
	}
	if (task != NULL) {
		isc_task_attach(task, &rbtdb->task);
	}
	RBTDB_UNLOCK(&rbtdb->lock, isc_rwlocktype_write);
}

static bool
ispersistent(dns_db_t *db) {
	UNUSED(db);
	return (false);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *onode;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	/* Note that the access to origin_node doesn't require a DB lock */
	onode = (dns_rbtnode_t *)rbtdb->origin_node;
	if (onode != NULL) {
		new_reference(rbtdb, onode, isc_rwlocktype_none);
		*nodep = rbtdb->origin_node;
	} else {
		result = ISC_R_NOTFOUND;
	}

	return (result);
}

static isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(stats != NULL);

	isc_stats_attach(stats, &rbtdb->cachestats);
	return (ISC_R_SUCCESS);
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	return (rbtdb->rrsetstats);
}

static isc_result_t
nodefullname(dns_db_t *db, dns_dbnode_t *node, dns_name_t *name) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *)node;
	isc_result_t result;

	REQUIRE(VALID_RBTDB(rbtdb));
	REQUIRE(node != NULL);
	REQUIRE(name != NULL);

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	result = dns_rbt_fullnamefromnode(rbtnode, name);
	RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);

	return (result);
}

static isc_result_t
setservestalettl(dns_db_t *db, dns_ttl_t ttl) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	/* currently no bounds checking.  0 means disable. */
	rbtdb->serve_stale_ttl = ttl;
	return (ISC_R_SUCCESS);
}

static isc_result_t
getservestalettl(dns_db_t *db, dns_ttl_t *ttl) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	*ttl = rbtdb->serve_stale_ttl;
	return (ISC_R_SUCCESS);
}

static isc_result_t
setservestalerefresh(dns_db_t *db, uint32_t interval) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	/* currently no bounds checking.  0 means disable. */
	rbtdb->serve_stale_refresh = interval;
	return (ISC_R_SUCCESS);
}

static isc_result_t
getservestalerefresh(dns_db_t *db, uint32_t *interval) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)db;

	REQUIRE(VALID_RBTDB(rbtdb));

	*interval = rbtdb->serve_stale_refresh;
	return (ISC_R_SUCCESS);
}

static dns_dbmethods_t cache_methods = { attach,
					 detach,
					 beginload,
					 endload,
					 dump,
					 currentversion,
					 newversion,
					 attachversion,
					 closeversion,
					 findnode,
					 cache_find,
					 cache_findzonecut,
					 attachnode,
					 detachnode,
					 expirenode,
					 printnode,
					 createiterator,
					 cache_findrdataset,
					 allrdatasets,
					 addrdataset,
					 subtractrdataset,
					 deleterdataset,
					 issecure,
					 nodecount,
					 ispersistent,
					 overmem,
					 settask,
					 getoriginnode,
					 NULL, /* transfernode */
					 NULL, /* getnsec3parameters */
					 NULL, /* findnsec3node */
					 NULL, /* setsigningtime */
					 NULL, /* getsigningtime */
					 NULL, /* resigned */
					 isdnssec,
					 getrrsetstats,
					 NULL, /* rpz_attach */
					 NULL, /* rpz_ready */
					 NULL, /* findnodeext */
					 NULL, /* findext */
					 setcachestats,
					 hashsize,
					 nodefullname,
					 NULL, /* getsize */
					 setservestalettl,
					 getservestalettl,
					 setservestalerefresh,
					 getservestalerefresh,
					 NULL };

isc_result_t
dns_rbtdb_create(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg, dns_db_t **dbp) {
	dns_rbtdb_t *rbtdb;
	isc_result_t result;
	int i;
	bool (*sooner)(void *, void *);
	isc_mem_t *hmctx = mctx;

	REQUIRE(type == dns_dbtype_cache);

	/* Keep the compiler happy. */
	UNUSED(driverarg);

	rbtdb = isc_mem_get(mctx, sizeof(*rbtdb));

	/*
	 * If argv[0] exists, it points to a memory context to use for heap
	 */
	if (argc != 0) {
		hmctx = (isc_mem_t *)argv[0];
	}

	memset(rbtdb, '\0', sizeof(*rbtdb));
	dns_name_init(&rbtdb->common.origin, NULL);
	rbtdb->common.attributes = 0;
	rbtdb->common.methods = &cache_methods;
	rbtdb->common.attributes |= DNS_DBATTR_CACHE;
	rbtdb->common.rdclass = rdclass;
	rbtdb->common.mctx = NULL;

	ISC_LIST_INIT(rbtdb->common.update_listeners);

	RBTDB_INITLOCK(&rbtdb->lock);

	isc_rwlock_init(&rbtdb->tree_lock, 0, 0);

	/*
	 * Initialize node_lock_count in a generic way to support future
	 * extension which allows the user to specify this value on creation.
	 * Note that when specified for a cache DB it must be larger than 1
	 * as commented with the definition of DEFAULT_CACHE_NODE_LOCK_COUNT.
	 */
	if (rbtdb->node_lock_count == 0) {
		rbtdb->node_lock_count = DEFAULT_CACHE_NODE_LOCK_COUNT;
	} else if (rbtdb->node_lock_count < 2) {
		result = ISC_R_RANGE;
		goto cleanup_tree_lock;
	}
	INSIST(rbtdb->node_lock_count < (1 << DNS_RBT_LOCKLENGTH));
	rbtdb->node_locks = isc_mem_get(mctx, rbtdb->node_lock_count *
						      sizeof(rbtdb_nodelock_t));

	rbtdb->cachestats = NULL;
	rbtdb->rrsetstats = NULL;

	result = dns_rdatasetstats_create(mctx, &rbtdb->rrsetstats);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_node_locks;
	}
	rbtdb->rdatasets = isc_mem_get(
		mctx, rbtdb->node_lock_count * sizeof(rdatasetheaderlist_t));
	for (i = 0; i < (int)rbtdb->node_lock_count; i++) {
		ISC_LIST_INIT(rbtdb->rdatasets[i]);
	}

	/*
	 * Create the heaps.
	 */
	rbtdb->heaps = isc_mem_get(hmctx, rbtdb->node_lock_count *
						  sizeof(isc_heap_t *));
	for (i = 0; i < (int)rbtdb->node_lock_count; i++) {
		rbtdb->heaps[i] = NULL;
	}
	sooner = ttl_sooner;
	for (i = 0; i < (int)rbtdb->node_lock_count; i++) {
		result = isc_heap_create(hmctx, sooner, set_index, 0,
					 &rbtdb->heaps[i]);
		if (result != ISC_R_SUCCESS) {
			goto cleanup_heaps;
		}
	}

	/*
	 * Create deadnode lists.
	 */
	rbtdb->deadnodes = isc_mem_get(mctx, rbtdb->node_lock_count *
						     sizeof(rbtnodelist_t));
	for (i = 0; i < (int)rbtdb->node_lock_count; i++) {
		ISC_LIST_INIT(rbtdb->deadnodes[i]);
	}

	rbtdb->active = rbtdb->node_lock_count;

	for (i = 0; i < (int)(rbtdb->node_lock_count); i++) {
		NODE_INITLOCK(&rbtdb->node_locks[i].lock);
		isc_refcount_init(&rbtdb->node_locks[i].references, 0);
		rbtdb->node_locks[i].exiting = false;
	}

	/*
	 * Attach to the mctx.  The database will persist so long as there
	 * are references to it, and attaching to the mctx ensures that our
	 * mctx won't disappear out from under us.
	 */
	isc_mem_attach(mctx, &rbtdb->common.mctx);
	isc_mem_attach(hmctx, &rbtdb->hmctx);

	/*
	 * Make a copy of the origin name.
	 */
	result = dns_name_dupwithoffsets(origin, mctx, &rbtdb->common.origin);
	if (result != ISC_R_SUCCESS) {
		free_rbtdb(rbtdb, false, NULL);
		return (result);
	}

	/*
	 * Make the Red-Black Trees.
	 */
	result = dns_rbt_create(mctx, delete_callback, rbtdb, &rbtdb->tree);
	if (result != ISC_R_SUCCESS) {
		free_rbtdb(rbtdb, false, NULL);
		return (result);
	}

	result = dns_rbt_create(mctx, delete_callback, rbtdb, &rbtdb->nsec);
	if (result != ISC_R_SUCCESS) {
		free_rbtdb(rbtdb, false, NULL);
		return (result);
	}

	result = dns_rbt_create(mctx, delete_callback, rbtdb, &rbtdb->nsec3);
	if (result != ISC_R_SUCCESS) {
		free_rbtdb(rbtdb, false, NULL);
		return (result);
	}

	/*
	 * Misc. Initialization.
	 */
	isc_refcount_init(&rbtdb->references, 1);
	rbtdb->attributes = 0;
	rbtdb->task = NULL;
	rbtdb->serve_stale_ttl = 0;

	/*
	 * Version Initialization.
	 */
	rbtdb->current_serial = 1;
	rbtdb->least_serial = 1;
	rbtdb->next_serial = 2;
	rbtdb->current_version = allocate_version(mctx, 1, 1, false);
	rbtdb->current_version->rbtdb = rbtdb;
	rbtdb->current_version->secure = dns_db_insecure;
	rbtdb->current_version->havensec3 = false;
	rbtdb->current_version->flags = 0;
	rbtdb->current_version->iterations = 0;
	rbtdb->current_version->hash = 0;
	rbtdb->current_version->salt_length = 0;
	memset(rbtdb->current_version->salt, 0,
	       sizeof(rbtdb->current_version->salt));
	isc_rwlock_init(&rbtdb->current_version->rwlock, 0, 0);
	rbtdb->current_version->records = 0;
	rbtdb->current_version->xfrsize = 0;
	rbtdb->future_version = NULL;
	ISC_LIST_INIT(rbtdb->open_versions);
	/*
	 * Keep the current version in the open list so that list operation
	 * won't happen in normal lookup operations.
	 */
	PREPEND(rbtdb->open_versions, rbtdb->current_version, link);

	rbtdb->common.magic = DNS_DB_MAGIC;
	rbtdb->common.impmagic = RBTDB_MAGIC;

	*dbp = (dns_db_t *)rbtdb;

	return (ISC_R_SUCCESS);

cleanup_heaps:
	if (rbtdb->heaps != NULL) {
		for (i = 0; i < (int)rbtdb->node_lock_count; i++) {
			if (rbtdb->heaps[i] != NULL) {
				isc_heap_destroy(&rbtdb->heaps[i]);
			}
		}
		isc_mem_put(hmctx, rbtdb->heaps,
			    rbtdb->node_lock_count * sizeof(isc_heap_t *));
	}

	if (rbtdb->rdatasets != NULL) {
		isc_mem_put(mctx, rbtdb->rdatasets,
			    rbtdb->node_lock_count *
				    sizeof(rdatasetheaderlist_t));
	}
	if (rbtdb->rrsetstats != NULL) {
		dns_stats_detach(&rbtdb->rrsetstats);
	}

cleanup_node_locks:
	isc_mem_put(mctx, rbtdb->node_locks,
		    rbtdb->node_lock_count * sizeof(rbtdb_nodelock_t));

cleanup_tree_lock:
	isc_rwlock_destroy(&rbtdb->tree_lock);
	RBTDB_DESTROYLOCK(&rbtdb->lock);
	isc_mem_put(mctx, rbtdb, sizeof(*rbtdb));
	return (result);
}

/*
 * Slabbed Rdataset Methods
 */

static void
rdataset_disassociate(dns_rdataset_t *rdataset) {
	dns_db_t *db = rdataset->private1;
	dns_dbnode_t *node = rdataset->private2;

	detachnode(db, &node);
}

static isc_result_t
rdataset_first(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->private3; /* RDATASLAB */
	unsigned int count;

	count = raw[0] * 256 + raw[1];
	if (count == 0) {
		rdataset->private5 = NULL;
		return (ISC_R_NOMORE);
	}

	if ((rdataset->attributes & DNS_RDATASETATTR_LOADORDER) == 0) {
		raw += DNS_RDATASET_COUNT;
	}

	raw += DNS_RDATASET_LENGTH;

	/*
	 * The privateuint4 field is the number of rdata beyond the
	 * cursor position, so we decrement the total count by one
	 * before storing it.
	 *
	 * If DNS_RDATASETATTR_LOADORDER is not set 'raw' points to the
	 * first record.  If DNS_RDATASETATTR_LOADORDER is set 'raw' points
	 * to the first entry in the offset table.
	 */
	count--;
	rdataset->privateuint4 = count;
	rdataset->private5 = raw;

	return (ISC_R_SUCCESS);
}

static isc_result_t
rdataset_next(dns_rdataset_t *rdataset) {
	unsigned int count;
	unsigned int length;
	unsigned char *raw; /* RDATASLAB */

	count = rdataset->privateuint4;
	if (count == 0) {
		return (ISC_R_NOMORE);
	}
	count--;
	rdataset->privateuint4 = count;

	/*
	 * Skip forward one record (length + 4) or one offset (4).
	 */
	raw = rdataset->private5;
#if DNS_RDATASET_FIXED
	if ((rdataset->attributes & DNS_RDATASETATTR_LOADORDER) == 0)
#endif /* DNS_RDATASET_FIXED */
	{
		length = raw[0] * 256 + raw[1];
		raw += length;
	}

	rdataset->private5 = raw + DNS_RDATASET_ORDER + DNS_RDATASET_LENGTH;

	return (ISC_R_SUCCESS);
}

static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = rdataset->private5; /* RDATASLAB */
	unsigned int length;
	isc_region_t r;
	unsigned int flags = 0;

	REQUIRE(raw != NULL);

	/*
	 * Find the start of the record if not already in private5
	 * then skip the length and order fields.
	 */
#if DNS_RDATASET_FIXED
	if ((rdataset->attributes & DNS_RDATASETATTR_LOADORDER) != 0) {
		unsigned int offset;
		offset = (raw[0] << 24) + (raw[1] << 16) + (raw[2] << 8) +
			 raw[3];
		raw = rdataset->private3;
		raw += offset;
	}
#endif /* if DNS_RDATASET_FIXED */

	length = raw[0] * 256 + raw[1];

	raw += DNS_RDATASET_ORDER + DNS_RDATASET_LENGTH;

	if (rdataset->type == dns_rdatatype_rrsig) {
		if (*raw & DNS_RDATASLAB_OFFLINE) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	r.length = length;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
	rdata->flags |= flags;
}

static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	dns_db_t *db = source->private1;
	dns_dbnode_t *node = source->private2;
	dns_dbnode_t *cloned_node = NULL;

	attachnode(db, node, &cloned_node);
	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);

	/*
	 * Reset iterator state.
	 */
	target->privateuint4 = 0;
	target->private5 = NULL;
}

static unsigned int
rdataset_count(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->private3; /* RDATASLAB */
	unsigned int count;

	count = raw[0] * 256 + raw[1];

	return (count);
}

static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *nsec, dns_rdataset_t *nsecsig) {
	dns_db_t *db = rdataset->private1;
	dns_dbnode_t *node = rdataset->private2;
	dns_dbnode_t *cloned_node;
	const struct noqname *noqname = rdataset->private6;

	cloned_node = NULL;
	attachnode(db, node, &cloned_node);
	nsec->methods = &slab_methods;
	nsec->rdclass = db->rdclass;
	nsec->type = noqname->type;
	nsec->covers = 0;
	nsec->ttl = rdataset->ttl;
	nsec->trust = rdataset->trust;
	nsec->private1 = rdataset->private1;
	nsec->private2 = rdataset->private2;
	nsec->private3 = noqname->neg;
	nsec->privateuint4 = 0;
	nsec->private5 = NULL;
	nsec->private6 = NULL;
	nsec->private7 = NULL;

	cloned_node = NULL;
	attachnode(db, node, &cloned_node);
	nsecsig->methods = &slab_methods;
	nsecsig->rdclass = db->rdclass;
	nsecsig->type = dns_rdatatype_rrsig;
	nsecsig->covers = noqname->type;
	nsecsig->ttl = rdataset->ttl;
	nsecsig->trust = rdataset->trust;
	nsecsig->private1 = rdataset->private1;
	nsecsig->private2 = rdataset->private2;
	nsecsig->private3 = noqname->negsig;
	nsecsig->privateuint4 = 0;
	nsecsig->private5 = NULL;
	nsec->private6 = NULL;
	nsec->private7 = NULL;

	dns_name_clone(&noqname->name, name);

	return (ISC_R_SUCCESS);
}

static isc_result_t
rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *nsec, dns_rdataset_t *nsecsig) {
	dns_db_t *db = rdataset->private1;
	dns_dbnode_t *node = rdataset->private2;
	dns_dbnode_t *cloned_node;
	const struct noqname *closest = rdataset->private7;

	cloned_node = NULL;
	attachnode(db, node, &cloned_node);
	nsec->methods = &slab_methods;
	nsec->rdclass = db->rdclass;
	nsec->type = closest->type;
	nsec->covers = 0;
	nsec->ttl = rdataset->ttl;
	nsec->trust = rdataset->trust;
	nsec->private1 = rdataset->private1;
	nsec->private2 = rdataset->private2;
	nsec->private3 = closest->neg;
	nsec->privateuint4 = 0;
	nsec->private5 = NULL;
	nsec->private6 = NULL;
	nsec->private7 = NULL;

	cloned_node = NULL;
	attachnode(db, node, &cloned_node);
	nsecsig->methods = &slab_methods;
	nsecsig->rdclass = db->rdclass;
	nsecsig->type = dns_rdatatype_rrsig;
	nsecsig->covers = closest->type;
	nsecsig->ttl = rdataset->ttl;
	nsecsig->trust = rdataset->trust;
	nsecsig->private1 = rdataset->private1;
	nsecsig->private2 = rdataset->private2;
	nsecsig->private3 = closest->negsig;
	nsecsig->privateuint4 = 0;
	nsecsig->private5 = NULL;
	nsec->private6 = NULL;
	nsec->private7 = NULL;

	dns_name_clone(&closest->name, name);

	return (ISC_R_SUCCESS);
}

static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	dns_rbtdb_t *rbtdb = rdataset->private1;
	dns_rbtnode_t *rbtnode = rdataset->private2;
	rdatasetheader_t *header = rdataset->private3;

	header--;
	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);
	header->trust = rdataset->trust = trust;
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);
}

static void
rdataset_expire(dns_rdataset_t *rdataset) {
	dns_rbtdb_t *rbtdb = rdataset->private1;
	dns_rbtnode_t *rbtnode = rdataset->private2;
	rdatasetheader_t *header = rdataset->private3;

	header--;
	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);
	expire_header(rbtdb, header, false, expire_flush);
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);
}

static void
rdataset_clearprefetch(dns_rdataset_t *rdataset) {
	dns_rbtdb_t *rbtdb = rdataset->private1;
	dns_rbtnode_t *rbtnode = rdataset->private2;
	rdatasetheader_t *header = rdataset->private3;

	header--;
	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);
	RDATASET_ATTR_CLR(header, RDATASET_ATTR_PREFETCH);
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp) {
	rbtdb_rdatasetiter_t *rbtiterator;

	rbtiterator = (rbtdb_rdatasetiter_t *)(*iteratorp);

	if (rbtiterator->common.version != NULL) {
		closeversion(rbtiterator->common.db,
			     &rbtiterator->common.version, false);
	}
	detachnode(rbtiterator->common.db, &rbtiterator->common.node);
	isc_mem_put(rbtiterator->common.db->mctx, rbtiterator,
		    sizeof(*rbtiterator));

	*iteratorp = NULL;
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator) {
	rbtdb_rdatasetiter_t *rbtiterator = (rbtdb_rdatasetiter_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(rbtiterator->common.db);
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	rdatasetheader_t *header, *top_next;
	rbtdb_serial_t serial = 1;
	isc_stdtime_t now = rbtiterator->common.now;

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_read);

	for (header = rbtnode->data; header != NULL; header = top_next) {
		top_next = header->next;
		do {
			if (header->serial <= serial && !IGNORE(header)) {
				/*
				 * Is this a "this rdataset doesn't exist"
				 * record?  Or is it too old in the cache?
				 *
				 * Note: unlike everywhere else, we
				 * check for now > header->rdh_ttl instead
				 * of ">=".  This allows ANY and RRSIG
				 *  queries for 0 TTL rdatasets to work.
				 */
				if (NONEXISTENT(header) ||
				    (now != 0 &&
				     (now - RBTDB_VIRTUAL) >
					     header->rdh_ttl +
						     rbtdb->serve_stale_ttl))
				{
					header = NULL;
				}
				break;
			} else {
				header = header->down;
			}
		} while (header != NULL);
		if (header != NULL) {
			break;
		}
	}

	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_read);

	rbtiterator->current = header;

	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator) {
	rbtdb_rdatasetiter_t *rbtiterator = (rbtdb_rdatasetiter_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(rbtiterator->common.db);
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	rdatasetheader_t *header, *top_next;
	rbtdb_serial_t serial = 1;
	isc_stdtime_t now = rbtiterator->common.now;
	rbtdb_rdatatype_t type, negtype;
	dns_rdatatype_t rdtype, covers;

	header = rbtiterator->current;
	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_read);

	type = header->type;
	rdtype = RBTDB_RDATATYPE_BASE(header->type);
	if (NEGATIVE(header)) {
		covers = RBTDB_RDATATYPE_EXT(header->type);
		negtype = RBTDB_RDATATYPE_VALUE(covers, 0);
	} else {
		negtype = RBTDB_RDATATYPE_VALUE(0, rdtype);
	}
	for (header = header->next; header != NULL; header = top_next) {
		top_next = header->next;
		/*
		 * If not walking back up the down list.
		 */
		if (header->type != type && header->type != negtype) {
			do {
				if (header->serial <= serial && !IGNORE(header))
				{
					/*
					 * Is this a "this rdataset doesn't
					 * exist" record?
					 *
					 * Note: unlike everywhere else, we
					 * check for now > header->ttl instead
					 * of ">=".  This allows ANY and RRSIG
					 * queries for 0 TTL rdatasets to work.
					 */
					if (NONEXISTENT(header) ||
					    (now != 0 &&
					     (now - RBTDB_VIRTUAL) >
						     header->rdh_ttl))
					{
						header = NULL;
					}
					break;
				} else {
					header = header->down;
				}
			} while (header != NULL);
			if (header != NULL) {
				break;
			}
		}
	}

	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_read);

	rbtiterator->current = header;

	if (header == NULL) {
		return (ISC_R_NOMORE);
	}

	return (ISC_R_SUCCESS);
}

static void
rdatasetiter_current(dns_rdatasetiter_t *iterator, dns_rdataset_t *rdataset) {
	rbtdb_rdatasetiter_t *rbtiterator = (rbtdb_rdatasetiter_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)(rbtiterator->common.db);
	dns_rbtnode_t *rbtnode = rbtiterator->common.node;
	rdatasetheader_t *header;

	header = rbtiterator->current;
	REQUIRE(header != NULL);

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_read);

	bind_rdataset(rbtdb, rbtnode, header, rbtiterator->common.now,
		      isc_rwlocktype_read, rdataset);

	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_read);
}

/*
 * Database Iterator Methods
 */

static inline void
reference_iter_node(rbtdb_dbiterator_t *rbtdbiter) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;
	dns_rbtnode_t *node = rbtdbiter->node;

	if (node == NULL) {
		return;
	}

	INSIST(rbtdbiter->tree_locked != isc_rwlocktype_none);
	reactivate_node(rbtdb, node, rbtdbiter->tree_locked);
}

static inline void
dereference_iter_node(rbtdb_dbiterator_t *rbtdbiter) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;
	dns_rbtnode_t *node = rbtdbiter->node;
	nodelock_t *lock;

	if (node == NULL) {
		return;
	}

	lock = &rbtdb->node_locks[node->locknum].lock;
	NODE_LOCK(lock, isc_rwlocktype_read);
	decrement_reference(rbtdb, node, isc_rwlocktype_read,
			    rbtdbiter->tree_locked, false);
	NODE_UNLOCK(lock, isc_rwlocktype_read);

	rbtdbiter->node = NULL;
}

static void
flush_deletions(rbtdb_dbiterator_t *rbtdbiter) {
	dns_rbtnode_t *node;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;
	bool was_read_locked = false;
	nodelock_t *lock;
	int i;

	if (rbtdbiter->delcnt != 0) {
		/*
		 * Note that "%d node of %d in tree" can report things like
		 * "flush_deletions: 59 nodes of 41 in tree".  This means
		 * That some nodes appear on the deletions list more than
		 * once.  Only the last occurrence will actually be deleted.
		 */
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_CACHE, ISC_LOG_DEBUG(1),
			      "flush_deletions: %d nodes of %d in tree",
			      rbtdbiter->delcnt,
			      dns_rbt_nodecount(rbtdb->tree));

		if (rbtdbiter->tree_locked == isc_rwlocktype_read) {
			RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
			was_read_locked = true;
		}
		RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
		rbtdbiter->tree_locked = isc_rwlocktype_write;

		for (i = 0; i < rbtdbiter->delcnt; i++) {
			node = rbtdbiter->deletions[i];
			lock = &rbtdb->node_locks[node->locknum].lock;

			NODE_LOCK(lock, isc_rwlocktype_read);
			decrement_reference(rbtdb, node, isc_rwlocktype_read,
					    rbtdbiter->tree_locked, false);
			NODE_UNLOCK(lock, isc_rwlocktype_read);
		}

		rbtdbiter->delcnt = 0;

		RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_write);
		if (was_read_locked) {
			RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
			rbtdbiter->tree_locked = isc_rwlocktype_read;
		} else {
			rbtdbiter->tree_locked = isc_rwlocktype_none;
		}
	}
}

static inline void
resume_iteration(rbtdb_dbiterator_t *rbtdbiter) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;

	REQUIRE(rbtdbiter->paused);
	REQUIRE(rbtdbiter->tree_locked == isc_rwlocktype_none);

	RWLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
	rbtdbiter->tree_locked = isc_rwlocktype_read;

	rbtdbiter->paused = false;
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp) {
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)(*iteratorp);
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)rbtdbiter->common.db;
	dns_db_t *db = NULL;

	if (rbtdbiter->tree_locked == isc_rwlocktype_read) {
		RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
		rbtdbiter->tree_locked = isc_rwlocktype_none;
	} else {
		INSIST(rbtdbiter->tree_locked == isc_rwlocktype_none);
	}

	dereference_iter_node(rbtdbiter);

	flush_deletions(rbtdbiter);

	dns_db_attach(rbtdbiter->common.db, &db);
	dns_db_detach(&rbtdbiter->common.db);

	dns_rbtnodechain_reset(&rbtdbiter->chain);
	dns_rbtnodechain_reset(&rbtdbiter->nsec3chain);
	isc_mem_put(db->mctx, rbtdbiter, sizeof(*rbtdbiter));
	dns_db_detach(&db);

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator) {
	isc_result_t result;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	dns_name_t *name, *origin;

	if (rbtdbiter->result != ISC_R_SUCCESS &&
	    rbtdbiter->result != ISC_R_NOTFOUND &&
	    rbtdbiter->result != DNS_R_PARTIALMATCH &&
	    rbtdbiter->result != ISC_R_NOMORE)
	{
		return (rbtdbiter->result);
	}

	if (rbtdbiter->paused) {
		resume_iteration(rbtdbiter);
	}

	dereference_iter_node(rbtdbiter);

	name = dns_fixedname_name(&rbtdbiter->name);
	origin = dns_fixedname_name(&rbtdbiter->origin);
	dns_rbtnodechain_reset(&rbtdbiter->chain);
	dns_rbtnodechain_reset(&rbtdbiter->nsec3chain);

	if (rbtdbiter->nsec3only) {
		rbtdbiter->current = &rbtdbiter->nsec3chain;
		result = dns_rbtnodechain_first(rbtdbiter->current,
						rbtdb->nsec3, name, origin);
	} else {
		rbtdbiter->current = &rbtdbiter->chain;
		result = dns_rbtnodechain_first(rbtdbiter->current, rbtdb->tree,
						name, origin);
		if (!rbtdbiter->nonsec3 && result == ISC_R_NOTFOUND) {
			rbtdbiter->current = &rbtdbiter->nsec3chain;
			result = dns_rbtnodechain_first(
				rbtdbiter->current, rbtdb->nsec3, name, origin);
		}
	}
	if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
		result = dns_rbtnodechain_current(rbtdbiter->current, NULL,
						  NULL, &rbtdbiter->node);
		if (result == ISC_R_SUCCESS) {
			rbtdbiter->new_origin = true;
			reference_iter_node(rbtdbiter);
		}
	} else {
		INSIST(result == ISC_R_NOTFOUND);
		result = ISC_R_NOMORE; /* The tree is empty. */
	}

	rbtdbiter->result = result;

	if (result != ISC_R_SUCCESS) {
		ENSURE(!rbtdbiter->paused);
	}

	return (result);
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator) {
	isc_result_t result;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	dns_name_t *name, *origin;

	if (rbtdbiter->result != ISC_R_SUCCESS &&
	    rbtdbiter->result != ISC_R_NOTFOUND &&
	    rbtdbiter->result != DNS_R_PARTIALMATCH &&
	    rbtdbiter->result != ISC_R_NOMORE)
	{
		return (rbtdbiter->result);
	}

	if (rbtdbiter->paused) {
		resume_iteration(rbtdbiter);
	}

	dereference_iter_node(rbtdbiter);

	name = dns_fixedname_name(&rbtdbiter->name);
	origin = dns_fixedname_name(&rbtdbiter->origin);
	dns_rbtnodechain_reset(&rbtdbiter->chain);
	dns_rbtnodechain_reset(&rbtdbiter->nsec3chain);

	result = ISC_R_NOTFOUND;
	if (rbtdbiter->nsec3only && !rbtdbiter->nonsec3) {
		rbtdbiter->current = &rbtdbiter->nsec3chain;
		result = dns_rbtnodechain_last(rbtdbiter->current, rbtdb->nsec3,
					       name, origin);
	}
	if (!rbtdbiter->nsec3only && result == ISC_R_NOTFOUND) {
		rbtdbiter->current = &rbtdbiter->chain;
		result = dns_rbtnodechain_last(rbtdbiter->current, rbtdb->tree,
					       name, origin);
	}
	if (result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN) {
		result = dns_rbtnodechain_current(rbtdbiter->current, NULL,
						  NULL, &rbtdbiter->node);
		if (result == ISC_R_SUCCESS) {
			rbtdbiter->new_origin = true;
			reference_iter_node(rbtdbiter);
		}
	} else {
		INSIST(result == ISC_R_NOTFOUND);
		result = ISC_R_NOMORE; /* The tree is empty. */
	}

	rbtdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator, const dns_name_t *name) {
	isc_result_t result, tresult;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	dns_name_t *iname, *origin;

	if (rbtdbiter->result != ISC_R_SUCCESS &&
	    rbtdbiter->result != ISC_R_NOTFOUND &&
	    rbtdbiter->result != DNS_R_PARTIALMATCH &&
	    rbtdbiter->result != ISC_R_NOMORE)
	{
		return (rbtdbiter->result);
	}

	if (rbtdbiter->paused) {
		resume_iteration(rbtdbiter);
	}

	dereference_iter_node(rbtdbiter);

	iname = dns_fixedname_name(&rbtdbiter->name);
	origin = dns_fixedname_name(&rbtdbiter->origin);
	dns_rbtnodechain_reset(&rbtdbiter->chain);
	dns_rbtnodechain_reset(&rbtdbiter->nsec3chain);

	if (rbtdbiter->nsec3only) {
		rbtdbiter->current = &rbtdbiter->nsec3chain;
		result = dns_rbt_findnode(rbtdb->nsec3, name, NULL,
					  &rbtdbiter->node, rbtdbiter->current,
					  DNS_RBTFIND_EMPTYDATA, NULL, NULL);
	} else if (rbtdbiter->nonsec3) {
		rbtdbiter->current = &rbtdbiter->chain;
		result = dns_rbt_findnode(rbtdb->tree, name, NULL,
					  &rbtdbiter->node, rbtdbiter->current,
					  DNS_RBTFIND_EMPTYDATA, NULL, NULL);
	} else {
		/*
		 * Stay on main chain if not found on either chain.
		 */
		rbtdbiter->current = &rbtdbiter->chain;
		result = dns_rbt_findnode(rbtdb->tree, name, NULL,
					  &rbtdbiter->node, rbtdbiter->current,
					  DNS_RBTFIND_EMPTYDATA, NULL, NULL);
		if (result == DNS_R_PARTIALMATCH) {
			dns_rbtnode_t *node = NULL;
			tresult = dns_rbt_findnode(
				rbtdb->nsec3, name, NULL, &node,
				&rbtdbiter->nsec3chain, DNS_RBTFIND_EMPTYDATA,
				NULL, NULL);
			if (tresult == ISC_R_SUCCESS) {
				rbtdbiter->node = node;
				rbtdbiter->current = &rbtdbiter->nsec3chain;
				result = tresult;
			}
		}
	}

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		tresult = dns_rbtnodechain_current(rbtdbiter->current, iname,
						   origin, NULL);
		if (tresult == ISC_R_SUCCESS) {
			rbtdbiter->new_origin = true;
			reference_iter_node(rbtdbiter);
		} else {
			result = tresult;
			rbtdbiter->node = NULL;
		}
	} else {
		rbtdbiter->node = NULL;
	}

	rbtdbiter->result = (result == DNS_R_PARTIALMATCH) ? ISC_R_SUCCESS
							   : result;

	return (result);
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator) {
	isc_result_t result;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_name_t *name, *origin;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;

	REQUIRE(rbtdbiter->node != NULL);

	if (rbtdbiter->result != ISC_R_SUCCESS) {
		return (rbtdbiter->result);
	}

	if (rbtdbiter->paused) {
		resume_iteration(rbtdbiter);
	}

	name = dns_fixedname_name(&rbtdbiter->name);
	origin = dns_fixedname_name(&rbtdbiter->origin);
	result = dns_rbtnodechain_prev(rbtdbiter->current, name, origin);
	if (result == ISC_R_NOMORE && !rbtdbiter->nsec3only &&
	    !rbtdbiter->nonsec3 && &rbtdbiter->nsec3chain == rbtdbiter->current)
	{
		rbtdbiter->current = &rbtdbiter->chain;
		dns_rbtnodechain_reset(rbtdbiter->current);
		result = dns_rbtnodechain_last(rbtdbiter->current, rbtdb->tree,
					       name, origin);
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_NOMORE;
		}
	}

	dereference_iter_node(rbtdbiter);

	if (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		rbtdbiter->new_origin = (result == DNS_R_NEWORIGIN);
		result = dns_rbtnodechain_current(rbtdbiter->current, NULL,
						  NULL, &rbtdbiter->node);
	}

	if (result == ISC_R_SUCCESS) {
		reference_iter_node(rbtdbiter);
	}

	rbtdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator) {
	isc_result_t result;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_name_t *name, *origin;
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;

	REQUIRE(rbtdbiter->node != NULL);

	if (rbtdbiter->result != ISC_R_SUCCESS) {
		return (rbtdbiter->result);
	}

	if (rbtdbiter->paused) {
		resume_iteration(rbtdbiter);
	}

	name = dns_fixedname_name(&rbtdbiter->name);
	origin = dns_fixedname_name(&rbtdbiter->origin);
	result = dns_rbtnodechain_next(rbtdbiter->current, name, origin);
	if (result == ISC_R_NOMORE && !rbtdbiter->nsec3only &&
	    !rbtdbiter->nonsec3 && &rbtdbiter->chain == rbtdbiter->current)
	{
		rbtdbiter->current = &rbtdbiter->nsec3chain;
		dns_rbtnodechain_reset(rbtdbiter->current);
		result = dns_rbtnodechain_first(rbtdbiter->current,
						rbtdb->nsec3, name, origin);
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_NOMORE;
		}
	}

	dereference_iter_node(rbtdbiter);

	if (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		rbtdbiter->new_origin = (result == DNS_R_NEWORIGIN);
		result = dns_rbtnodechain_current(rbtdbiter->current, NULL,
						  NULL, &rbtdbiter->node);
	}
	if (result == ISC_R_SUCCESS) {
		reference_iter_node(rbtdbiter);
	}

	rbtdbiter->result = result;

	return (result);
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_rbtnode_t *node = rbtdbiter->node;
	isc_result_t result;
	dns_name_t *nodename = dns_fixedname_name(&rbtdbiter->name);
	dns_name_t *origin = dns_fixedname_name(&rbtdbiter->origin);

	REQUIRE(rbtdbiter->result == ISC_R_SUCCESS);
	REQUIRE(rbtdbiter->node != NULL);

	if (rbtdbiter->paused) {
		resume_iteration(rbtdbiter);
	}

	if (name != NULL) {
		if (rbtdbiter->common.relative_names) {
			origin = NULL;
		}
		result = dns_name_concatenate(nodename, origin, name, NULL);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		if (rbtdbiter->common.relative_names && rbtdbiter->new_origin) {
			result = DNS_R_NEWORIGIN;
		}
	} else {
		result = ISC_R_SUCCESS;
	}

	new_reference(rbtdb, node, isc_rwlocktype_none);

	*nodep = rbtdbiter->node;

	if (iterator->cleaning && result == ISC_R_SUCCESS) {
		isc_result_t expire_result;

		/*
		 * If the deletion array is full, flush it before trying
		 * to expire the current node.  The current node can't
		 * fully deleted while the iteration cursor is still on it.
		 */
		if (rbtdbiter->delcnt == DELETION_BATCH_MAX) {
			flush_deletions(rbtdbiter);
		}

		expire_result = expirenode(iterator->db, *nodep, 0);

		/*
		 * expirenode() currently always returns success.
		 */
		if (expire_result == ISC_R_SUCCESS && node->down == NULL) {
			rbtdbiter->deletions[rbtdbiter->delcnt++] = node;
			isc_refcount_increment(&node->references);
		}
	}

	return (result);
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	dns_rbtdb_t *rbtdb = (dns_rbtdb_t *)iterator->db;
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;

	if (rbtdbiter->result != ISC_R_SUCCESS &&
	    rbtdbiter->result != ISC_R_NOTFOUND &&
	    rbtdbiter->result != DNS_R_PARTIALMATCH &&
	    rbtdbiter->result != ISC_R_NOMORE)
	{
		return (rbtdbiter->result);
	}

	if (rbtdbiter->paused) {
		return (ISC_R_SUCCESS);
	}

	rbtdbiter->paused = true;

	if (rbtdbiter->tree_locked != isc_rwlocktype_none) {
		INSIST(rbtdbiter->tree_locked == isc_rwlocktype_read);
		RWUNLOCK(&rbtdb->tree_lock, isc_rwlocktype_read);
		rbtdbiter->tree_locked = isc_rwlocktype_none;
	}

	flush_deletions(rbtdbiter);

	return (ISC_R_SUCCESS);
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	rbtdb_dbiterator_t *rbtdbiter = (rbtdb_dbiterator_t *)iterator;
	dns_name_t *origin = dns_fixedname_name(&rbtdbiter->origin);

	if (rbtdbiter->result != ISC_R_SUCCESS) {
		return (rbtdbiter->result);
	}

	dns_name_copy(origin, name);
	return (ISC_R_SUCCESS);
}

static void
setownercase(rdatasetheader_t *header, const dns_name_t *name) {
	unsigned int i;
	bool fully_lower;

	/*
	 * We do not need to worry about label lengths as they are all
	 * less than or equal to 63.
	 */
	memset(header->upper, 0, sizeof(header->upper));
	fully_lower = true;
	for (i = 0; i < name->length; i++) {
		if (isupper(name->ndata[i])) {
			header->upper[i / 8] |= 1 << (i % 8);
			fully_lower = false;
		}
	}
	RDATASET_ATTR_SET(header, RDATASET_ATTR_CASESET);
	if (fully_lower) {
		RDATASET_ATTR_SET(header, RDATASET_ATTR_CASEFULLYLOWER);
	}
}

static void
rdataset_setownercase(dns_rdataset_t *rdataset, const dns_name_t *name) {
	dns_rbtdb_t *rbtdb = rdataset->private1;
	dns_rbtnode_t *rbtnode = rdataset->private2;
	unsigned char *raw = rdataset->private3; /* RDATASLAB */
	rdatasetheader_t *header;

	header = (struct rdatasetheader *)(raw - sizeof(*header));

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_write);
	setownercase(header, name);
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_write);
}

static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name) {
	dns_rbtdb_t *rbtdb = rdataset->private1;
	dns_rbtnode_t *rbtnode = rdataset->private2;
	unsigned char *raw = rdataset->private3; /* RDATASLAB */
	rdatasetheader_t *header = NULL;
	uint8_t mask = (1 << 7);
	uint8_t bits = 0;

	header = (struct rdatasetheader *)(raw - sizeof(*header));

	NODE_LOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		  isc_rwlocktype_read);

	if (!CASESET(header)) {
		goto unlock;
	}

	if (CASEFULLYLOWER(header)) {
		for (size_t i = 0; i < name->length; i++) {
			name->ndata[i] = tolower(name->ndata[i]);
		}
	} else {
		for (size_t i = 0; i < name->length; i++) {
			if (mask == (1 << 7)) {
				bits = header->upper[i / 8];
				mask = 1;
			} else {
				mask <<= 1;
			}

			name->ndata[i] = ((bits & mask) != 0)
						 ? toupper(name->ndata[i])
						 : tolower(name->ndata[i]);
		}
	}

unlock:
	NODE_UNLOCK(&rbtdb->node_locks[rbtnode->locknum].lock,
		    isc_rwlocktype_read);
}

struct rbtdb_glue {
	struct rbtdb_glue *next;
	dns_fixedname_t fixedname;
	dns_rdataset_t rdataset_a;
	dns_rdataset_t sigrdataset_a;
	dns_rdataset_t rdataset_aaaa;
	dns_rdataset_t sigrdataset_aaaa;
};

typedef struct {
	rbtdb_glue_t *glue_list;
	dns_rbtdb_t *rbtdb;
	rbtdb_version_t *rbtversion;
} rbtdb_glue_additionaldata_ctx_t;

static void
free_gluelist(rbtdb_glue_t *glue_list, dns_rbtdb_t *rbtdb) {
	rbtdb_glue_t *cur, *cur_next;

	if (glue_list == (void *)-1) {
		return;
	}

	cur = glue_list;
	while (cur != NULL) {
		cur_next = cur->next;

		if (dns_rdataset_isassociated(&cur->rdataset_a)) {
			dns_rdataset_disassociate(&cur->rdataset_a);
		}
		if (dns_rdataset_isassociated(&cur->sigrdataset_a)) {
			dns_rdataset_disassociate(&cur->sigrdataset_a);
		}

		if (dns_rdataset_isassociated(&cur->rdataset_aaaa)) {
			dns_rdataset_disassociate(&cur->rdataset_aaaa);
		}
		if (dns_rdataset_isassociated(&cur->sigrdataset_aaaa)) {
			dns_rdataset_disassociate(&cur->sigrdataset_aaaa);
		}

		dns_rdataset_invalidate(&cur->rdataset_a);
		dns_rdataset_invalidate(&cur->sigrdataset_a);
		dns_rdataset_invalidate(&cur->rdataset_aaaa);
		dns_rdataset_invalidate(&cur->sigrdataset_aaaa);

		isc_mem_put(rbtdb->common.mctx, cur, sizeof(*cur));
		cur = cur_next;
	}
}

static void
free_gluetable(rbtdb_version_t *version) {
	dns_rbtdb_t *rbtdb;
	size_t size, i;

	RWLOCK(&version->glue_rwlock, isc_rwlocktype_write);

	rbtdb = version->rbtdb;

	for (i = 0; i < HASHSIZE(version->glue_table_bits); i++) {
		rbtdb_glue_table_node_t *cur, *cur_next;

		cur = version->glue_table[i];
		while (cur != NULL) {
			cur_next = cur->next;
			/* isc_refcount_decrement(&cur->node->references); */
			cur->node = NULL;
			free_gluelist(cur->glue_list, rbtdb);
			cur->glue_list = NULL;
			isc_mem_put(rbtdb->common.mctx, cur, sizeof(*cur));
			cur = cur_next;
		}
		version->glue_table[i] = NULL;
	}

	size = HASHSIZE(version->glue_table_bits) *
	       sizeof(*version->glue_table);
	isc_mem_put(rbtdb->common.mctx, version->glue_table, size);

	RWUNLOCK(&version->glue_rwlock, isc_rwlocktype_write);
}

static isc_result_t
rdataset_addglue(dns_rdataset_t *rdataset, dns_dbversion_t *version,
		 dns_message_t *msg) {
	UNUSED(rdataset);
	UNUSED(version);
	UNUSED(msg);

	INSIST(0);

	/* UNREACHABLE */
}

/*%
 * Routines for LRU-based cache management.
 */

/*%
 * See if a given cache entry that is being reused needs to be updated
 * in the LRU-list.  From the LRU management point of view, this function is
 * expected to return true for almost all cases.  When used with threads,
 * however, this may cause a non-negligible performance penalty because a
 * writer lock will have to be acquired before updating the list.
 * If DNS_RBTDB_LIMITLRUUPDATE is defined to be non 0 at compilation time, this
 * function returns true if the entry has not been updated for some period of
 * time.  We differentiate the NS or glue address case and the others since
 * experiments have shown that the former tends to be accessed relatively
 * infrequently and the cost of cache miss is higher (e.g., a missing NS records
 * may cause external queries at a higher level zone, involving more
 * transactions).
 *
 * Caller must hold the node (read or write) lock.
 */
static inline bool
need_headerupdate(rdatasetheader_t *header, isc_stdtime_t now) {
	if (RDATASET_ATTR_GET(header, (RDATASET_ATTR_NONEXISTENT |
				       RDATASET_ATTR_ANCIENT |
				       RDATASET_ATTR_ZEROTTL)) != 0)
	{
		return (false);
	}

#if DNS_RBTDB_LIMITLRUUPDATE
	if (header->type == dns_rdatatype_ns ||
	    (header->trust == dns_trust_glue &&
	     (header->type == dns_rdatatype_a ||
	      header->type == dns_rdatatype_aaaa)))
	{
		/*
		 * Glue records are updated if at least DNS_RBTDB_LRUUPDATE_GLUE
		 * seconds have passed since the previous update time.
		 */
		return (header->last_used + DNS_RBTDB_LRUUPDATE_GLUE <= now);
	}

	/*
	 * Other records are updated if DNS_RBTDB_LRUUPDATE_REGULAR seconds
	 * have passed.
	 */
	return (header->last_used + DNS_RBTDB_LRUUPDATE_REGULAR <= now);
#else
	UNUSED(now);

	return (true);
#endif /* if DNS_RBTDB_LIMITLRUUPDATE */
}

/*%
 * Update the timestamp of a given cache entry and move it to the head
 * of the corresponding LRU list.
 *
 * Caller must hold the node (write) lock.
 *
 * Note that the we do NOT touch the heap here, as the TTL has not changed.
 */
static void
update_header(dns_rbtdb_t *rbtdb, rdatasetheader_t *header, isc_stdtime_t now) {
	/* To be checked: can we really assume this? XXXMLG */
	INSIST(ISC_LINK_LINKED(header, link));

	ISC_LIST_UNLINK(rbtdb->rdatasets[header->node->locknum], header, link);
	header->last_used = now;
	ISC_LIST_PREPEND(rbtdb->rdatasets[header->node->locknum], header, link);
}

/*%
 * Purge some expired and/or stale (i.e. unused for some period) cache entries
 * under an overmem condition.  To recover from this condition quickly, up to
 * 2 entries will be purged.  This process is triggered while adding a new
 * entry, and we specifically avoid purging entries in the same LRU bucket as
 * the one to which the new entry will belong.  Otherwise, we might purge
 * entries of the same name of different RR types while adding RRsets from a
 * single response (consider the case where we're adding A and AAAA glue records
 * of the same NS name).
 */
static void
overmem_purge(dns_rbtdb_t *rbtdb, unsigned int locknum_start, isc_stdtime_t now,
	      bool tree_locked) {
	rdatasetheader_t *header, *header_prev;
	unsigned int locknum;
	int purgecount = 2;

	for (locknum = (locknum_start + 1) % rbtdb->node_lock_count;
	     locknum != locknum_start && purgecount > 0;
	     locknum = (locknum + 1) % rbtdb->node_lock_count)
	{
		NODE_LOCK(&rbtdb->node_locks[locknum].lock,
			  isc_rwlocktype_write);

		header = isc_heap_element(rbtdb->heaps[locknum], 1);
		if (header && header->rdh_ttl < now - RBTDB_VIRTUAL) {
			expire_header(rbtdb, header, tree_locked, expire_ttl);
			purgecount--;
		}

		for (header = ISC_LIST_TAIL(rbtdb->rdatasets[locknum]);
		     header != NULL && purgecount > 0; header = header_prev)
		{
			header_prev = ISC_LIST_PREV(header, link);
			/*
			 * Unlink the entry at this point to avoid checking it
			 * again even if it's currently used someone else and
			 * cannot be purged at this moment.  This entry won't be
			 * referenced any more (so unlinking is safe) since the
			 * TTL was reset to 0.
			 */
			ISC_LIST_UNLINK(rbtdb->rdatasets[locknum], header,
					link);
			expire_header(rbtdb, header, tree_locked, expire_lru);
			purgecount--;
		}

		NODE_UNLOCK(&rbtdb->node_locks[locknum].lock,
			    isc_rwlocktype_write);
	}
}

static void
expire_header(dns_rbtdb_t *rbtdb, rdatasetheader_t *header, bool tree_locked,
	      expire_t reason) {
	set_ttl(rbtdb, header, 0);
	mark_header_ancient(rbtdb, header);

	/*
	 * Caller must hold the node (write) lock.
	 */

	if (isc_refcount_current(&header->node->references) == 0) {
		/*
		 * If no one else is using the node, we can clean it up now.
		 * We first need to gain a new reference to the node to meet a
		 * requirement of decrement_reference().
		 */
		new_reference(rbtdb, header->node, isc_rwlocktype_write);
		decrement_reference(rbtdb, header->node, isc_rwlocktype_write,
				    tree_locked ? isc_rwlocktype_write
						: isc_rwlocktype_none,
				    false);

		if (rbtdb->cachestats == NULL) {
			return;
		}

		switch (reason) {
		case expire_ttl:
			isc_stats_increment(rbtdb->cachestats,
					    dns_cachestatscounter_deletettl);
			break;
		case expire_lru:
			isc_stats_increment(rbtdb->cachestats,
					    dns_cachestatscounter_deletelru);
			break;
		default:
			break;
		}
	}
}
