/*  Copyright (C) 2015-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/packet/wire.h>
#include <libknot/rrset.h>
#include <libknot/rrtype/nsec.h>
#include <libknot/rrtype/rrsig.h>
#include <dnssec/error.h>

#include "lib/defines.h"
#include "lib/dnssec/nsec.h"

bool kr_nsec_bitmap_contains_type(const uint8_t *bm, uint16_t bm_size, uint16_t type)
{
	if (!bm || bm_size == 0) {
		return false;
	}

	const uint8_t type_hi = (type >> 8);
	const uint8_t type_lo = (type & 0xff);
	const uint8_t bitmap_idx = (type_lo >> 3);
	const uint8_t bitmap_bit_mask = 1 << (7 - (type_lo & 0x07));

	size_t bm_pos = 0;
	while (bm_pos + 3 <= bm_size) {
		uint8_t win = bm[bm_pos++];
		uint8_t win_size = bm[bm_pos++];
		/* Check remaining window length. */
		if (win_size < 1 || bm_pos + win_size > bm_size)
			return false;
		/* Check that we have a correct window. */
		if (win == type_hi) {
			if (bitmap_idx < win_size) {
				return bm[bm_pos + bitmap_idx] & bitmap_bit_mask;
			}
			return false;
		} else {
			bm_pos += win_size;
		}
	}

	return false;
}

/**
 * Check whether the NSEC RR proves that there is no closer match for <SNAME, SCLASS>.
 * @param nsec  NSEC RRSet.
 * @param sname Searched name.
 * @return      0 or error code.
 */
static int nsec_nonamematch(const knot_rrset_t *nsec, const knot_dname_t *sname)
{
	assert(nsec && sname);
	const knot_dname_t *next = knot_nsec_next(&nsec->rrs);
	/* If NSEC 'owner' >= 'next', it means that there is nothing after 'owner' */
	const bool is_last_nsec = (knot_dname_cmp(nsec->owner, next) >= 0);
	if (is_last_nsec) { /* SNAME is after owner => provably doesn't exist */
		if (knot_dname_cmp(nsec->owner, sname) < 0) {
			return kr_ok();
		}
	} else {
		/* Prove that SNAME is between 'owner' and 'next' */
		if ((knot_dname_cmp(nsec->owner, sname) < 0) && (knot_dname_cmp(sname, next) < 0)) {
			return kr_ok();
		}
	}
	return kr_error(EINVAL);
}

#define FLG_NOEXIST_RRTYPE (1 << 0) /**< <SNAME, SCLASS> exists, <SNAME, SCLASS, STYPE> does not exist. */
#define FLG_NOEXIST_RRSET  (1 << 1) /**< <SNAME, SCLASS> does not exist. */
#define FLG_NOEXIST_WILDCARD (1 << 2) /**< No wildcard covering <SNAME, SCLASS> exists. */
#define FLG_NOEXIST_CLOSER (1 << 3) /**< Wildcard covering <SNAME, SCLASS> exists, but doesn't match STYPE. */


/**
 * According to set flags determine whether NSEC proving
 * RRset or RRType non-existense has been found.
 * @param f Flags to inspect.
 * @return  True if required NSEC exists.
 */
#define kr_nsec_rrset_noexist(f) \
        ((f) & (FLG_NOEXIST_RRTYPE | FLG_NOEXIST_RRSET))
/**
 * According to set flags determine whether wildcard non-existense
 * has been proven.
 * @param f Flags to inspect.
 * @return  True if wildcard not exists.
 */
#define kr_nsec_wcard_noexist(f) ((f) & FLG_NOEXIST_WILDCARD)

/**
 * According to set flags determine whether authenticated denial of existence has been proven.
 * @param f Flags to inspect.
 * @return  True if denial of existence proven.
 */
#define kr_nsec_existence_denied(f) \
	((kr_nsec_rrset_noexist(f)) && (kr_nsec_wcard_noexist(f)))

/**
 * Name error response check (RFC4035 3.1.3.2; RFC4035 5.4, bullet 2).
 * @note Returned flags must be checked in order to prove denial.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param name  Name to be checked.
 * @param pool
 * @return      0 or error code.
 */
static int name_error_response_check_rr(int *flags, const knot_rrset_t *nsec,
                                        const knot_dname_t *name)
{
	assert(flags && nsec && name);

	if (nsec_nonamematch(nsec, name) == 0) {
		*flags |= FLG_NOEXIST_RRSET;
	}

	/* Try to find parent wildcard that is proved by this NSEC. */ 
	uint8_t namebuf[KNOT_DNAME_MAXLEN];
	int ret = knot_dname_to_wire(namebuf, name, sizeof(namebuf));
	if (ret < 0)
		return ret;
	knot_dname_t *ptr = namebuf;
	while (ptr[0]) {
		/* Remove leftmost label and replace it with '\1*'. */
		ptr = (uint8_t *) knot_wire_next_label(ptr, NULL);
		*(--ptr) = '*';
		*(--ptr) = 1;
		/* True if this wildcard provably doesn't exist. */
		if (nsec_nonamematch(nsec, ptr) == 0) {
			*flags |= FLG_NOEXIST_WILDCARD;
			break;
		}
		/* Remove added leftmost asterisk. */
		ptr += 2;
	}

	return kr_ok();
}

int kr_nsec_name_error_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                      const knot_dname_t *sname)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC) {
			continue;
		}
		int ret = name_error_response_check_rr(&flags, rrset, sname);
		if (ret != 0) {
			return ret;
		}
	}

	return kr_nsec_existence_denied(flags) ? kr_ok() : kr_error(ENOENT);
}

/**
 * Returns the labels from the covering RRSIG RRs.
 * @note The number must be the same in all covering RRSIGs.
 * @param nsec NSEC RR.
 * @param sec  Packet section.
 * @param      Number of labels or (negative) error code.
 */
static int coverign_rrsig_labels(const knot_rrset_t *nsec, const knot_pktsection_t *sec)
{
	assert(nsec && sec);

	int ret = kr_error(ENOENT);

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if ((rrset->type != KNOT_RRTYPE_RRSIG) ||
		    (!knot_dname_is_equal(rrset->owner, nsec->owner))) {
			continue;
		}

		for (uint16_t j = 0; j < rrset->rrs.rr_count; ++j) {
			if (knot_rrsig_type_covered(&rrset->rrs, j) != KNOT_RRTYPE_NSEC) {
				continue;
			}

			if (ret < 0) {
				ret = knot_rrsig_labels(&rrset->rrs, j);
			} else {
				if (ret != knot_rrsig_labels(&rrset->rrs, j)) {
					return kr_error(EINVAL);
				}
			}
		}
	}

	return ret;
}

/**
 * Perform check of RR type existence denial according to RFC4035 5.4, bullet 1.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param type  Type to be checked.
 * @return      0 or error code.
 */
static int no_data_response_check_rrtype(int *flags, const knot_rrset_t *nsec,
                                         uint16_t type)
{
	assert(flags && nsec);

	uint8_t *bm = NULL;
	uint16_t bm_size;
	knot_nsec_bitmap(&nsec->rrs, &bm, &bm_size);
	if (!bm) {
		return kr_error(EINVAL);
	}

	if (!kr_nsec_bitmap_contains_type(bm, bm_size, type)) {
		/* The type is not listed in the NSEC bitmap. */
		*flags |= FLG_NOEXIST_RRTYPE;
	}

	return kr_ok();
}

/**
 * Perform check for RR type wildcard existence denial according to RFC4035 5.4, bullet 1.
 * @param flags Flags to be set according to check outcome.
 * @param nsec  NSEC RR.
 * @param sec   Packet section to work with.
 * @return      0 or error code.
 */
static int no_data_wildcard_existence_check(int *flags, const knot_rrset_t *nsec,
                                            const knot_pktsection_t *sec)
{
	assert(flags && nsec && sec);

	int rrsig_labels = coverign_rrsig_labels(nsec, sec);
	if (rrsig_labels < 0) {
		return rrsig_labels;
	}
	int nsec_labels = knot_dname_labels(nsec->owner, NULL);
	if (nsec_labels < 0) {
		return nsec_labels;
	}

	if (rrsig_labels == nsec_labels) {
		*flags |= FLG_NOEXIST_WILDCARD;
	}

	return kr_ok();
}

/**
 * Perform check for NSEC wildcard existence that covers sname and
 * have no stype bit set.
 * @param pkt   Packet structure to be processed.
 * @param sec   Packet section to work with.
 * @param sname Queried domain name.
 * @param stype Queried type.
 * @return      0 or error code.
 */
static int wildcard_match_check(const knot_pkt_t *pkt, const knot_pktsection_t *sec,
				const knot_dname_t *sname, uint16_t stype)
{
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC) {
			continue;
		}
		if (!knot_dname_is_wildcard(rrset->owner)) {
			continue;
		}
		int wcard_labels = knot_dname_labels(rrset->owner, NULL);
		int common_labels = knot_dname_matched_labels(rrset->owner, sname);
		int rrsig_labels = coverign_rrsig_labels(rrset, sec);
		if (wcard_labels < 1 ||
		    common_labels != wcard_labels - 1 ||
		    common_labels != rrsig_labels) {
			continue;
		}
		int ret = no_data_response_check_rrtype(&flags, rrset, stype);
		if (ret != 0) {
			return ret;
		}
	}
	return (flags & FLG_NOEXIST_RRTYPE) ? kr_ok() : kr_error(ENOENT);
}

int kr_nsec_no_data_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                   const knot_dname_t *sname, uint16_t stype)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC) {
			continue;
		}
		if (knot_dname_is_equal(rrset->owner, sname)) {
			int ret = no_data_response_check_rrtype(&flags, rrset, stype);
			if (ret != 0) {
				return ret;
			}
		}
	}

	return (flags & FLG_NOEXIST_RRTYPE) ? kr_ok() : kr_error(ENOENT);
}

int kr_nsec_wildcard_answer_response_check(const knot_pkt_t *pkt, knot_section_t section_id,
                                           const knot_dname_t *sname)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC) {
			continue;
		}
		if (nsec_nonamematch(rrset, sname) == 0) {
			return kr_ok();
		}
	}

	return kr_error(ENOENT);
}

int kr_nsec_existence_denial(const knot_pkt_t *pkt, knot_section_t section_id,
                             const knot_dname_t *sname, uint16_t stype)
{
	const knot_pktsection_t *sec = knot_pkt_section(pkt, section_id);
	if (!sec || !sname) {
		return kr_error(EINVAL);
	}

	int flags = 0;
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *rrset = knot_pkt_rr(sec, i);
		if (rrset->type != KNOT_RRTYPE_NSEC) {
			continue;
		}
		/* NSEC proves that name exists, but has no data (RFC4035 4.9, 1) */
		if (knot_dname_is_equal(rrset->owner, sname)) {
			no_data_response_check_rrtype(&flags, rrset, stype);
		} else {
			/* NSEC proves that name doesn't exist (RFC4035, 4.9, 2) */
			name_error_response_check_rr(&flags, rrset, sname);
		}
		no_data_wildcard_existence_check(&flags, rrset, sec);
	}
	if (kr_nsec_existence_denied(flags)) {
		/* denial of existence proved accordignly to 4035 5.4 -
		 * NSEC proving either rrset non-existance or
		 * qtype non-existance has been found,
		 * and no wildcard expansion occured.
		 */
		return kr_ok();
	} else if (kr_nsec_rrset_noexist(flags)) {
		/* NSEC proving either rrset non-existance or
		 * qtype non-existance has been found,
		 * but wildcard expansion occurs.
		 * Try to find matching wildcard and check
		 * corresponding types.
		 */
		return wildcard_match_check(pkt, sec, sname, stype);
	}
	return kr_error(ENOENT);
}

int kr_nsec_ref_to_unsigned(const knot_pkt_t *pkt)
{
	int nsec_found = 0;
	uint8_t *bm = NULL;
	uint16_t bm_size = 0;
	const knot_pktsection_t *sec = knot_pkt_section(pkt, KNOT_AUTHORITY);
	if (!sec) {
		return kr_error(EINVAL);
	}
	for (unsigned i = 0; i < sec->count; ++i) {
		const knot_rrset_t *ns = knot_pkt_rr(sec, i);
		if (ns->type == KNOT_RRTYPE_DS) {
			return kr_error(EEXIST);
		}
		if (ns->type != KNOT_RRTYPE_NS) {
			continue;
		}
		nsec_found = 0;
		for (unsigned j = 0; j < sec->count; ++j) {
			const knot_rrset_t *nsec = knot_pkt_rr(sec, j);
			if (nsec->type == KNOT_RRTYPE_DS) {
				return kr_error(EEXIST);
			}
			if (nsec->type != KNOT_RRTYPE_NSEC) {
				continue;
			}
			/* nsec found
			 * check if owner name matches the delegation name
			 */
			if (!knot_dname_is_equal(nsec->owner, ns->owner)) {
				/* nsec does not match the delegation */
				continue;
			}
			nsec_found = 1;
			knot_nsec_bitmap(&nsec->rrs, &bm, &bm_size);
			if (!bm) {
				return kr_error(EINVAL);
			}
			if (kr_nsec_bitmap_contains_type(bm, bm_size,
							  KNOT_RRTYPE_NS) &&
			    !kr_nsec_bitmap_contains_type(bm, bm_size,
							  KNOT_RRTYPE_DS) &&
			    !kr_nsec_bitmap_contains_type(bm, bm_size,
							  KNOT_RRTYPE_SOA)) {
				/* rfc4035, 5.2 */
				return kr_ok();
			}
		}
		if (nsec_found) {
			/* nsec which owner matches
			 * the delegation name was found,
			 * but nsec type bitmap contains wrong types
			 */
			return kr_error(EINVAL);
		} else {
			/* nsec that matches delegation was not found */
			return kr_error(DNSSEC_NOT_FOUND);
		}
	}

	return kr_error(EINVAL);
}

int kr_nsec_matches_name_and_type(const knot_rrset_t *nsec,
				   const knot_dname_t *name, uint16_t type)
{
	if (!nsec || !name) {
		return (EINVAL);
	}
	if (!knot_dname_is_equal(nsec->owner, name)) {
		return (ENOENT);
	}
	uint8_t *bm = NULL;
	uint16_t bm_size = 0;
	knot_nsec_bitmap(&nsec->rrs, &bm, &bm_size);
	if (!bm) {
		return kr_error(EINVAL);
	}
	if (!kr_nsec_bitmap_contains_type(bm, bm_size, type)) {
		return (ENOENT);
	}
	return kr_ok();
}
