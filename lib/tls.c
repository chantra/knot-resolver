/*
 * Copyright (C) 2016 American Civil Liberties Union (ACLU)
 *               2016-2018 CZ.NIC, z.s.p.o
 *
 * Initial Author: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
 *                 Ondřej Surý <ondrej@sury.org>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "lib/tls.h"
#include "lib/utils.h"

int tls_client_params_clear(map_t *tls_client_paramlist, const char *addr, uint16_t port)
{
	if (!tls_client_paramlist || !addr) {
		return kr_error(EINVAL);
	}

	/* Parameters are OK */

	char key[INET6_ADDRSTRLEN + 6];
	size_t keylen = sizeof(key);
	if (kr_straddr_join(addr, port, key, &keylen) != kr_ok()) {
		return kr_error(EINVAL);
	}

	struct tls_client_paramlist_entry *entry = map_get(tls_client_paramlist, key);
	if (entry != NULL) {
		client_paramlist_entry_unref(entry);
		map_del(tls_client_paramlist, key);
	}

	return kr_ok();
}

int tls_client_params_set(map_t *tls_client_paramlist,
			  const char *addr, uint16_t port,
			  const char *param, tls_client_param_t param_type)
{
	if (!tls_client_paramlist || !addr) {
		return kr_error(EINVAL);
	}

	/* TLS_CLIENT_PARAM_CA can be empty */
	if (param_type == TLS_CLIENT_PARAM_HOSTNAME ||
	    param_type == TLS_CLIENT_PARAM_PIN) {
		if (param == NULL || param[0] == 0) {
			return kr_error(EINVAL);
		}
	}

	/* Parameters are OK */

	char key[INET6_ADDRSTRLEN + 6];
	size_t keylen = sizeof(key);
	if (kr_straddr_join(addr, port, key, &keylen) != kr_ok()) {
		kr_log_error("[tls_client] warning: '%s' is not a valid ip address, ignoring\n", addr);
		return kr_ok();
	}

	bool is_first_entry = false;
	struct tls_client_paramlist_entry *entry = map_get(tls_client_paramlist, key);
	if (entry == NULL) {
		entry = calloc(1, sizeof(struct tls_client_paramlist_entry));
		if (entry == NULL) {
			return kr_error(ENOMEM);
		}
		is_first_entry  = true;
		int ret = gnutls_certificate_allocate_credentials(&entry->credentials);
		if (ret != GNUTLS_E_SUCCESS) {
			free(entry);
			kr_log_error("[tls_client] error: gnutls_certificate_allocate_credentials() fails (%s)\n",
				     gnutls_strerror_name(ret));
			return kr_error(ENOMEM);
		}
		gnutls_certificate_set_verify_function(entry->credentials, client_verify_certificate);
		client_paramlist_entry_ref(entry);
	}

	int ret = kr_ok();

	if (param_type == TLS_CLIENT_PARAM_HOSTNAME) {
		const char *hostname = param;
		bool already_exists = false;
		for (size_t i = 0; i < entry->hostnames.len; ++i) {
			if (strcmp(entry->hostnames.at[i], hostname) == 0) {
				kr_log_error("[tls_client] error: hostname '%s' for address '%s' already was set, ignoring\n", hostname, key);
				already_exists = true;
				break;
			}
		}
		if (!already_exists) {
			const char *value = strdup(hostname);
			if (!value) {
				ret = kr_error(ENOMEM);
			} else if (array_push(entry->hostnames, value) < 0) {
				free ((void *)value);
				ret = kr_error(ENOMEM);
			}
		}
	} else if (param_type == TLS_CLIENT_PARAM_CA) {
		/* Import ca files only when hostname is already set */
		if (entry->hostnames.len == 0) {
			return kr_error(ENOENT);
		}
		const char *ca_file = param;
		bool already_exists = false;
		for (size_t i = 0; i < entry->ca_files.len; ++i) {
			const char *imported_ca = entry->ca_files.at[i];
			if (imported_ca[0] == 0 && (ca_file == NULL || ca_file[0] == 0)) {
				kr_log_error("[tls_client] error: system ca for address '%s' already was set, ignoring\n", key);
				already_exists = true;
				break;
			} else if (strcmp(imported_ca, ca_file) == 0) {
				kr_log_error("[tls_client] error: ca file '%s' for address '%s' already was set, ignoring\n", ca_file, key);
				already_exists = true;
				break;
			}
		}
		if (!already_exists) {
			const char *value = strdup(ca_file != NULL ? ca_file : "");
			if (!value) {
				ret = kr_error(ENOMEM);
			} else if (array_push(entry->ca_files, value) < 0) {
				free ((void *)value);
				ret = kr_error(ENOMEM);
			} else if (value[0] == 0) {
				int res = gnutls_certificate_set_x509_system_trust (entry->credentials);
				if (res <= 0) {
					kr_log_error("[tls_client] failed to import certs from system store (%s)\n",
						     gnutls_strerror_name(res));
					/* value will be freed at cleanup */
					ret = kr_error(EINVAL);
				} else {
					kr_log_verbose("[tls_client] imported %d certs from system store\n", res);
				}
			} else {
				int res = gnutls_certificate_set_x509_trust_file(entry->credentials, value,
										 GNUTLS_X509_FMT_PEM);
				if (res <= 0) {
					kr_log_error("[tls_client] failed to import certificate file '%s' (%s)\n",
						     value, gnutls_strerror_name(res));
					/* value will be freed at cleanup */
					ret = kr_error(EINVAL);
				} else {
					kr_log_verbose("[tls_client] imported %d certs from file '%s'\n",
							res, value);

				}
			}
		}
	} else if (param_type == TLS_CLIENT_PARAM_PIN) {
		const char *pin = param;
		for (size_t i = 0; i < entry->pins.len; ++i) {
			if (strcmp(entry->pins.at[i], pin) == 0) {
				kr_log_error("[tls_client] warning: pin '%s' for address '%s' already was set, ignoring\n", pin, key);
				return kr_ok();
			}
		}
		const void *value = strdup(pin);
		if (!value) {
			ret = kr_error(ENOMEM);
		} else if (array_push(entry->pins, value) < 0) {
			free ((void *)value);
			ret = kr_error(ENOMEM);
		}
	}

	if ((ret == kr_ok()) && is_first_entry) {
		bool fail = (map_set(tls_client_paramlist, key, entry) != 0);
		if (fail) {
			ret = kr_error(ENOMEM);
		}
	}

	if ((ret != kr_ok()) && is_first_entry) {
		client_paramlist_entry_unref(entry);
	}

	return ret;
}

int tls_client_params_free(map_t *tls_client_paramlist)
{
	if (!tls_client_paramlist) {
		return kr_error(EINVAL);
	}

	map_walk(tls_client_paramlist, client_paramlist_entry_clear, NULL);
	map_clear(tls_client_paramlist);

	return kr_ok();
}
