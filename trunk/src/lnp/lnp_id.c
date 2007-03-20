/*
 * Copyright (C) 2004 by
 * - Diego "iamscared" Aranha <iamscared[at]users.sourceforge.net> &
 * - Edans "snade" Flavius <snade[at]users.sourceforge.net>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/** 
 * @file lnp_id.c
 * @ingroup lnp
 */
 
#include <stdlib.h>
#include <stdio.h> 
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <libfreedom/layer_net.h>
#include <libfreedom/liblog.h>
#include <util/util_crypto.h>

#include "lnp_config.h"
#include "lnp_packets.h"
#include "lnp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/* */
static u_char my_public_key[LNP_PUBLIC_KEY_LENGTH];
/* */
static util_hash_function_t *hash;

/*============================================================================*/
/* Public data definitions.                                                   */
/*============================================================================*/

/** */
net_id_t my_id;

/** */
RSA *my_key_pair;

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int lnp_id_initialize() {
	FILE *public_key_file;
	FILE *private_key_file;
	u_char *pointer;
	
	hash = util_get_hash("sha1");
	
	if (hash == NULL) {
		return LNP_ERROR;
	}
	
	if ((public_key_file = fopen(lnp_get_public_key_file(), "r")) == NULL) {
		return LNP_ERROR;
	}
	
	if ((private_key_file = fopen(lnp_get_private_key_file(), "r")) == NULL) {
		fclose(public_key_file);
		return LNP_ERROR;
	}

	my_key_pair = RSA_new();

	d2i_RSAPublicKey_fp(public_key_file, &my_key_pair);
	d2i_RSAPrivateKey_fp(private_key_file, &my_key_pair);
	
	my_public_key[MPINT_SIGNAL_OFFSET] = 0;
	*((int *)my_public_key) = htonl(LNP_PUBLIC_KEY_LENGTH -
			MPINT_SIGNAL_LENGTH - MPINT_SIZE_LENGTH);
	pointer = &my_public_key[MPINT_BEGINNING_OFFSET];
	i2d_RSAPublicKey(my_key_pair, &pointer);

	hash->function(my_id, &my_public_key[MPINT_BEGINNING_OFFSET],
			LNP_PUBLIC_KEY_LENGTH - MPINT_SIGNAL_LENGTH - MPINT_SIZE_LENGTH);

	liblog_debug(LAYER_NET, "ID %02X%02X%02X%02X%02X...\n",
			my_id[0], my_id[1], my_id[2], my_id[3], my_id[4]);
	
	fclose(private_key_file);
	fclose(public_key_file);
	
	return LNP_OK;
}
/******************************************************************************/
void lnp_id_finalize() {
	free(my_public_key);

	RSA_free(my_key_pair);
}
/******************************************************************************/
int lnp_get_public_key(u_char *data, int max) {
	if (max < LNP_PUBLIC_KEY_LENGTH) {
		return LNP_ERROR;
	}
	memcpy(data, my_public_key, LNP_PUBLIC_KEY_LENGTH);
	
	return LNP_PUBLIC_KEY_LENGTH;
}
/******************************************************************************/
