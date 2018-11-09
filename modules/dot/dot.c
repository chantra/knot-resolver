/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/**
 * @file dot.c
 * @brief NS name based DoT SPKI discovery.
 *
 * The module provides a mechanism to discover SPKI pinning via specially
 * formatted NS names.
 */

#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>

#include "contrib/base64.h"
#include "daemon/engine.h"
#include "daemon/tls.h"
#include "lib/module.h"
#include "lib/layer.h"
#include "lib/resolve.h"
#include "lib/utils.h"

/* Defaults */
#define VERBOSE_MSG(qry, fmt...) QRVERBOSE(qry, "dot",  fmt)
#define ERR_MSG(fmt, ...) kr_log_error("[     ][dot] " fmt, ## __VA_ARGS__)

#define SHA256_SIZE 32
#define PINLEN  (((32) * 8 + 4)/6) + 3 + 1

/** Useful for returning from module properties. */
static char * bool2jsonstr(bool val)
{
	char *result = NULL;
	if (-1 == asprintf(&result, "{ \"result\": %s }", val ? "true" : "false"))
		result = NULL;
	return result;
}

static int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize) {
  int buffer = 0;
  int bitsLeft = 0;
  int count = 0;
  for (const uint8_t *ptr = encoded; count < bufSize && *ptr; ++ptr) {
    uint8_t ch = *ptr;

    buffer <<= 5;

    // Look up one base32 digit
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
      ch = (ch & 0x1F) - 1;
    } else if (ch >= '2' && ch <= '7') {
      ch -= '2' - 26;
    } else {
      return -1;
    }

    buffer |= ch;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      result[count++] = buffer >> (bitsLeft - 8);
      bitsLeft -= 8;
    }
  }
  if (count < bufSize) {
    result[count] = '\000';
  }
  return count;
}

static int query(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_module *module = ctx->api->data;
	if (!module->data) {
		ERR_MSG("Loaded but not enabled! Run dot.enable() in your config");
		return KR_STATE_DONE;	// not enabled
	}

	struct engine *engine = module->data;
	struct network *net = &engine->net;

	struct kr_query *qry = ctx->req->current_query;

	if (!qry || ctx->state & (KR_STATE_FAIL)) {
		return ctx->state;
	}

	const knot_pktsection_t *auth_sec = knot_pkt_section(pkt, KNOT_AUTHORITY);
	for (unsigned k = 0; k < auth_sec->count; ++k) {
		const knot_rrset_t *rr = knot_pkt_rr(auth_sec, k);
		if (rr->type == KNOT_RRTYPE_NS) {
			/* Fetch glue for each NS */
			knot_rdata_t *rdata_i = rr->rrs.rdata;
			for (unsigned i = 0; i < rr->rrs.count;
					++i, rdata_i = knot_rdataset_next(rdata_i)) {
				const knot_dname_t *ns_name = knot_ns_name(rdata_i);
				char *dname_str = knot_dname_to_str(NULL, ns_name, 0);
				if (dname_str == NULL) {
					ERR_MSG("Failed to convert domain to str");
					continue;
				}
				// Not a dot- NS
				if (strncasecmp(dname_str, "dot-", 4) != 0) {
					free(dname_str);
					continue;
				}

				char *dot_index = strstr(dname_str, ".");
				*dot_index = '\0';
				/*
				for(int x=0; x < strlen(dname_str); x++) {
					dname_str[x] ^= 0x20;
				}
				*/
				char sha[SHA256_SIZE];
				char pin[PINLEN] = { 0 };
				if(base32_decode((const uint8_t *)dname_str+4, (uint8_t *)sha, SHA256_SIZE) != SHA256_SIZE) {
					ERR_MSG("Failed to decode %s\n", dname_str+4);
				}
				base64_encode((const uint8_t *)sha, sizeof(sha), (uint8_t *)pin, PINLEN);
				// Find glue records
				const knot_pktsection_t *add_sec = knot_pkt_section(pkt, KNOT_ADDITIONAL);
		        for (unsigned j = 0; j < add_sec->count; ++j) {
		                const knot_rrset_t *rradd = knot_pkt_rr(add_sec, j);
		                if (knot_dname_is_equal(ns_name, rradd->owner) &&
		                    (rradd->type == KNOT_RRTYPE_A || rradd->type == KNOT_RRTYPE_AAAA)) {
		                        // Found a match
								ERR_MSG("Found a match for %s with pin %s type %d\n", dname_str, pin, rradd->type);
								// FIXME need to iterate over each RR
								knot_rdata_t *rdata = knot_rdataset_at(&rradd->rrs, 0);
								if(rdata == NULL) {
									ERR_MSG("No record found for %s type %d\n", dname_str, rradd->type);
									continue;
								}
								char ipaddr[INET6_ADDRSTRLEN];
								if(!inet_ntop(rradd->type == KNOT_RRTYPE_A ? AF_INET : AF_INET6, rdata->data, ipaddr, sizeof(ipaddr))) {
									ERR_MSG("Failed to convert IP address to string\n");
									continue;
								}

								int ok = tls_client_params_set(&net->tls_client_params,
									ipaddr, 853, pin, TLS_CLIENT_PARAM_PIN);
								if(!ok) {
									ERR_MSG("Failed to add pin %s for host %s\n", pin, dname_str);
								}

		                }
		        }
				free(dname_str);
			}

		}
	}

	return KR_STATE_DONE;
}

static char* dot_enable(void *env, struct kr_module *module, const char *args)
{
	module->data = env;
	return bool2jsonstr(true);
}

/*
 * Module implementation.
 */

KR_EXPORT
const kr_layer_api_t *dot_layer(struct kr_module *module)
{
	static kr_layer_api_t _layer = {
		.consume = &query,
	};
	/* Store module reference */
	_layer.data = module;
	return &_layer;
}


/** Basic initialization */
KR_EXPORT
int dot_init(struct kr_module *module)
{
	return kr_ok();
}

/** Release all resources. */
KR_EXPORT
int dot_deinit(struct kr_module *module)
{
	return kr_ok();
}

KR_EXPORT
struct kr_prop *dot_props(void)
{
	static struct kr_prop prop_list[] = {
		{ &dot_enable,   "enable", "Enable DoT pin discovery", },
	    { NULL, NULL, NULL }
	};
	return prop_list;
}

KR_MODULE_EXPORT(dot);

#undef VERBOSE_MSG
