/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef DNS_RDATASET_H
#define DNS_RDATASET_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Rdataset
 *
 * A DNS rdataset is a handle that can be associated with a collection of
 * rdata all having a common owner name, class, and type.
 *
 * The dns_rdataset_t type is like a "virtual class".  To actually use
 * rdatasets, an implementation of the method suite (e.g. "slabbed rdata") is
 * required.
 *
 * XXX <more> XXX
 *
 * MP:
 *	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *	No anticipated impact.
 *
 * Resources:
 *	<TBS>
 *
 * Security:
 *	No anticipated impact.
 *
 * Standards:
 *	None.
 */

#include <isc/boolean.h>
#include <isc/buffer.h>
#include <isc/lang.h>
#include <isc/stdtime.h>

#include <dns/types.h>
#include <dns/result.h>

ISC_LANG_BEGINDECLS

typedef struct dns_rdatasetmethods {
	void			(*disassociate)(dns_rdataset_t *rdataset);
	dns_result_t		(*first)(dns_rdataset_t *rdataset);
	dns_result_t		(*next)(dns_rdataset_t *rdataset);
	void			(*current)(dns_rdataset_t *rdataset,
					   dns_rdata_t *rdata);
	void			(*clone)(dns_rdataset_t *source,
					 dns_rdataset_t *target);
	unsigned int		(*count)(dns_rdataset_t *rdataset);
} dns_rdatasetmethods_t;

#define DNS_RDATASET_MAGIC		0x444E5352U	/* DNSR. */
#define DNS_RDATASET_VALID(rdataset)	((rdataset) != NULL && \
					 (rdataset)->magic == \
					  DNS_RDATASET_MAGIC)

/*
 * Direct use of this structure by clients is strongly discouraged, except
 * for the 'link' field which may be used however the client wishes.  The
 * 'private', 'current', and 'index' fields MUST NOT be changed by clients.
 * rdataset implementations may change any of the fields.
 */
struct dns_rdataset {
	unsigned int			magic;		/* XXX ? */
	dns_rdatasetmethods_t *		methods;
	ISC_LINK(dns_rdataset_t)	link;
	/*
	 * XXX do we need these, or should they be retrieved by methods?
	 * Leaning towards the latter, since they are not frequently required
	 * once you have the rdataset.
	 */
	dns_rdataclass_t		rdclass;
	dns_rdatatype_t			type;
	dns_ttl_t			ttl;
	dns_trust_t			trust;
	dns_rdatatype_t			covers;
	/*
	 * attributes
	 */
	unsigned int			attributes;
	/*
	 * These are for use by the rdataset implementation, and MUST NOT
	 * be changed by clients.
	 */
	void *				private1;
	void *				private2;
	void *				private3;
	void *				private4;
	void *				private5;
};

#define DNS_RDATASETATTR_QUESTION	0x0001
#define DNS_RDATASETATTR_RENDERED	0x0002		/* used by message.c */
#define DNS_RDATASETATTR_ANSWERED	0x0004		/* used by server */

void
dns_rdataset_init(dns_rdataset_t *rdataset);
/*
 * Make 'rdataset' a valid, disassociated rdataset.
 *
 * Requires:
 *	'rdataset' is not NULL.
 *
 * Ensures:
 *	'rdataset' is a valid, disassociated rdataset.
 */

void
dns_rdataset_invalidate(dns_rdataset_t *rdataset);
/*
 * Invalidate 'rdataset'.
 *
 * Requires:
 *	'rdataset' is a valid, disassociated rdataset.
 *
 * Ensures:
 *	If assertion checking is enabled, future attempts to use 'rdataset'
 *	without initializing it will cause an assertion failure.
 */

void
dns_rdataset_disassociate(dns_rdataset_t *rdataset);
/*
 * Disassociate 'rdataset' from its rdata, allowing it to be reused.
 *
 * Notes:
 *	The client must ensure it has no references to rdata in the rdataset
 *	before disassociating.
 *
 * Requires:
 *	'rdataset' is a valid, associated rdataset.
 *
 * Ensures:
 *	'rdataset' is a valid, disassociated rdataset.
 */

isc_boolean_t
dns_rdataset_isassociated(dns_rdataset_t *rdataset);
/*
 * Is 'rdataset' associated?
 *
 * Requires:
 *	'rdataset' is a valid rdataset.
 *
 * Returns:
 *	ISC_TRUE			'rdataset' is associated.
 *	ISC_FALSE			'rdataset' is not associated.
 */

void
dns_rdataset_makequestion(dns_rdataset_t *rdataset, dns_rdataclass_t rdclass,
			  dns_rdatatype_t type);
/*
 * Make 'rdataset' a valid, associated, question rdataset, with a
 * question class of 'rdclass' and type 'type'.
 *
 * Notes:
 *	Question rdatasets have a class and type, but no rdata.
 *
 * Requires:
 *	'rdataset' is a valid, disassociated rdataset.
 *
 * Ensures:
 *	'rdataset' is a valid, associated, question rdataset.
 */

void
dns_rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target);
/*
 * Make 'target' refer to the same rdataset as 'source'.
 *
 * Requires:
 *	'source' is a valid, associated rdataset.
 *
 *	'target' is a valid, dissociated rdataset.
 *
 * Ensures:
 *	'target' references the same rdataset as 'source.
 */

unsigned int
dns_rdataset_count(dns_rdataset_t *rdataset);
/*
 * Return the number of records in 'rdataset'.
 *
 * Requires:
 *	'rdataset' is a valid, associated rdataset.
 *
 * Returns:
 *	The number of records in 'rdataset'.	
 */

dns_result_t
dns_rdataset_first(dns_rdataset_t *rdataset);
/*
 * Move the rdata cursor to the first rdata in the rdataset (if any).
 *
 * Requires:
 *	'rdataset' is a valid, associated rdataset.
 *
 * Returns:
 *	DNS_R_SUCCESS
 *	DNS_R_NOMORE			There are no rdata in the set.
 */

dns_result_t
dns_rdataset_next(dns_rdataset_t *rdataset);
/*
 * Move the rdata cursor to the next rdata in the rdataset (if any).
 *
 * Requires:
 *	'rdataset' is a valid, associated rdataset.
 *
 * Returns:
 *	DNS_R_SUCCESS
 *	DNS_R_NOMORE			There are no more rdata in the set.
 */

void
dns_rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
/*
 * Make 'rdata' refer to the current rdata.
 *
 * Requires:
 *	'rdataset' is a valid, associated rdataset.
 *
 *	The rdata cursor of 'rdataset' is at a valid location (i.e. the
 *	result of last call to a cursor movement command was DNS_R_SUCCESS).
 *
 * Ensures:
 *	'rdata' refers to the rdata at the rdata cursor location of
 *	'rdataset'.
 */

dns_result_t
dns_rdataset_totext(dns_rdataset_t *rdataset,
		    dns_name_t *owner_name,
		    isc_boolean_t omit_final_dot,
		    isc_boolean_t no_rdata_or_ttl,
		    isc_buffer_t *target);
/*
 * Convert 'rdataset' to text format, storing the result in 'target'.
 *
 * Notes:
 *	The rdata cursor position will be changed.
 *
 *	The no_rdata_or_ttl should normally be ISC_FALSE.  If it is ISC_TRUE
 *	the ttl and rdata fields are not printed.  This is mainly for use
 *	in the question section.
 *
 *	XXX may need to add 'origin' parameter if we go with that in rdata.
 *
 * Requires:
 *	'rdataset' is a valid rdataset.
 *
 *	'rdataset' is not empty.
 *
 * XXX Supply more Requires and Ensures XXX
 */

dns_result_t
dns_rdataset_towire(dns_rdataset_t *rdataset,
		    dns_name_t *owner_name,
		    dns_compress_t *cctx,
		    isc_buffer_t *target,
		    unsigned int *countp);
/*
 * Convert 'rdataset' to wire format, compressing names as specified
 * in 'cctx', and storing the result in 'target'.
 *
 * Notes:
 *	The rdata cursor position will be changed.
 *
 *	The number of RRs added to target will be added to *countp.
 *
 * Requires:
 *	'rdataset' is a valid rdataset.
 *
 *	'rdataset' is not empty.
 *
 *	'countp' is a valid pointer.
 *
 * Ensures:
 *	On a return of DNS_R_SUCCESS, 'target' contains a wire format
 *	for the data contained in 'rdataset'.  Any error return leaves
 *	the buffer unchanged.
 *
 *	*countp has been incremented by the number of RRs added to
 *	target.
 *
 * Returns:
 *	DNS_R_SUCCESS		- all ok
 *	DNS_R_NOSPACE		- 'target' doesn't have enough room
 *
 *	Any error returned by dns_rdata_towire(), dns_rdataset_next(),
 *	dns_name_towire().
 */

dns_result_t
dns_rdataset_additionaldata(dns_rdataset_t *rdataset,
			    dns_additionaldatafunc_t add, void *arg);
/*
 * For each rdata in rdataset, call 'add' for each name and type in the
 * rdata which is subject to additional section processing.
 *
 * Requires:
 *
 *	'rdataset' is a valid, non-question rdataset.
 *
 *	'add' is a valid dns_additionaldatafunc_t
 *
 * Ensures:
 *
 *	If successful, dns_rdata_additionaldata() will have been called for
 *	each rdata in 'rdataset'.
 *
 *	If a call to dns_rdata_additionaldata() is not successful, the
 *	result returned will be the result of dns_rdataset_additionaldata().
 *
 * Returns:
 *
 *	DNS_R_SUCCESS
 *
 *	Any error that dns_rdata_additionaldata() can return.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_RDATASET_H */
