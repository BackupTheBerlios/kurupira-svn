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
 * @file libless_signature.h
 * 
 * Interface of the Certificateless Public Key Cryptography signature module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_SIGNATURE_H_
	#define _LIBLESS_SIGNATURE_H_

	#include "libless_types.h"

	/**
	 * Generates a set of system parameters and a master key to be used by
	 * the centralized authority.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] params       - the resulting system parameters
	 * @param[out] master_key   - the resulting master key
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_signature_setup(libless_t *env, libless_params_t *params,
		libless_master_t *master_key);

	/**
	 * Extracts a user partial private key from its identifier.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] key          - the resulting partial private key
	 * @param[in] id            - the user identifier
	 * @param[in] id_len        - the length of the identifier in bytes
	 * @param[in] master        - the central authority master key
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_signature_extract(libless_t *env, libless_partial_t *key,
		unsigned char *id, int id_len, libless_master_t master,
		libless_params_t parameters);


	/**
	 * Generates a user secret.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] secret       - the resulting secret
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_signature_set_secret(libless_t *env, libless_secret_t *secret,
		libless_params_t parameters);

	/**
	 * Generates a user public key from the user secret.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] public_key   - the resulting public key
	 * @param[in] secret        - the user secret
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_signature_set_public(libless_t *env, libless_public_t *public_key,
		libless_secret_t secret, libless_params_t parameters);

	/**
	 * Constructs a private key from the partial private key and the user 
	 * secret.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] private      - the resulting private key
	 * @param[in] secret        - the user secret
	 * @param[in] partial       - the user partial private key
	 * @param[in] parameters    - the system parameters.
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_signature_set_private(libless_t *env, libless_private_t *private,
		libless_secret_t secret, libless_partial_t partial,
		libless_params_t parameters);

	/**
	 * Signs data with the user identifier and key pair.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] signature    - the resulting signature
	 * @param[in] in            - the data to sign
	 * @param[in] in_len        - the number of bytes to sign
	 * @param[in] id            - the user identifier
	 * @param[in] id_len        - the length of the identifier in bytes
	 * @param[in] public_key    - the user public key
	 * @param[in] private_key   - the signing private key
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_sign(libless_t *env, libless_signature_t * signature,
		unsigned char *in, int in_len, unsigned char *id, int id_len,
		libless_public_t public_key, libless_private_t private_key,
		libless_params_t parameters);

	/**
	 * Deciphers a cryptogram with the user private key.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] verified     - a boolean indicating if the signature is valid
	 * @param[in] signature     - the signature to verify 
	 * @param[in] in            - the data signed
	 * @param[in] in_len        - the number of bytes signed 
	 * @param[in] id            - the user identifier
	 * @param[in] id_len        - the length of the identifier in bytes
	 * @param[in] public_key    - the user public key
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_verify(libless_t *env, int *verified,
		libless_signature_t signature, unsigned char *in, int in_len,
		unsigned char *id, int id_len, libless_public_t public_key,
		libless_params_t parameters);

#endif /* !_LIBLESS_SIGNATURE_H_ */
