/*
 * Copyright (C) 2006-07 The Kurupira Project
 * 
 * Kurupira is the legal property of its developers, whose names are not listed
 * here. Please refer to the COPYRIGHT file.
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
 * @file libless_types.c
 * 
 * Implementation of the type management routines.
 * 
 * @version $Header$
 * @ingroup libless
 */
 
#include <stdio.h>
 
#include "libless_types.h"
 
/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void libless_parameters_init(libless_params_t *parameters) {
	parameters->group1 = NULL;
	parameters->group2 = NULL;
	parameters->generator1 = NULL;
	parameters->generator2 = NULL;
	parameters->public = NULL;
	parameters->pairing = NULL;
	parameters->prime = NULL;
	parameters->factor = NULL;
}

void libless_parameters_clean(libless_params_t *parameters) {
	EC_GROUP_free(parameters->group1);
	EC_GROUP_free(parameters->group2);
	EC_POINT_free(parameters->generator1);
	EC_POINT_free(parameters->generator2);
	EC_POINT_free(parameters->public);
	BN_free(parameters->pairing);
	BN_free(parameters->prime);
	BN_free(parameters->factor);
}

void libless_master_init(libless_master_t *master_key) {
	*master_key = NULL;
}

void libless_master_clean(libless_master_t *master_key) {
	BN_free(*master_key);
}

void libless_partial_init(libless_partial_t *partial_key) {
	*partial_key = NULL;
}

void libless_partial_clean(libless_partial_t *partial_key) {
	EC_POINT_free(*partial_key);
	*partial_key = NULL;
}

void libless_secret_init(libless_secret_t *secret) {
	*secret = NULL;
}

void libless_secret_clean(libless_secret_t *secret) {
	BN_free(*secret);
	*secret = NULL;
}

void libless_public_init(libless_public_t *public_key) {
	public_key->pairing = NULL;
	public_key->point = NULL;
}

void libless_public_clean(libless_public_t *public_key) {
	BN_free(public_key->pairing);
	EC_POINT_free(public_key->point);
}

void libless_private_init(libless_private_t *private_key) {
	libless_secret_init(&(private_key->secret));
	libless_partial_init(&(private_key->partial));
}

void libless_private_clean(libless_private_t *private_key) {
	libless_secret_clean(&(private_key->secret));
	libless_partial_clean(&(private_key->partial));
}

void libless_signature_init(libless_signature_t *signature) {
	signature->image = NULL;
	signature->hash = NULL;
	signature->hash_len = 0;
}

void libless_signature_clean(libless_signature_t *signature) {
	free(signature->image);
	free(signature->hash);
	signature->image = NULL;
	signature->hash = NULL;
	signature->hash_len = 0;
}

void libless_ciphertext_init(libless_ciphertext_t *encrypted) {
	encrypted->image = NULL;
	encrypted->data = NULL;
	encrypted->envelope = NULL;
	encrypted->data_len = 0;
	encrypted->env_len = 0;	
}

void libless_ciphertext_clean(libless_ciphertext_t *encrypted) {
	EC_POINT_free(encrypted->image);
	free(encrypted->data);
	free(encrypted->envelope);
	encrypted->image = NULL;
	encrypted->data = NULL;
	encrypted->envelope = NULL;
	encrypted->data_len = 0;
	encrypted->env_len = 0;
}
