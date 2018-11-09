/*  Copyright (C) 2016 American Civil Liberties Union (ACLU)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "lib/defines.h"
#include "lib/generic/map.h"

typedef enum tls_client_param {
	TLS_CLIENT_PARAM_NONE = 0,
	TLS_CLIENT_PARAM_PIN,
	TLS_CLIENT_PARAM_HOSTNAME,
	TLS_CLIENT_PARAM_CA,
} tls_client_param_t;

/*! Clear (remove) TLS parameters for given address. */
int tls_client_params_clear(map_t *tls_client_paramlist, const char *addr, uint16_t port);

/*! Set TLS authentication parameters for given address.
 * Note: hostnames must be imported before ca files,
 *       otherwise ca files will not be imported at all.
 */
int tls_client_params_set(map_t *tls_client_paramlist,
			  const char *addr, uint16_t port,
			  const char *param, tls_client_param_t param_type);

/*! Free TLS authentication parameters. */
int tls_client_params_free(map_t *tls_client_paramlist);
