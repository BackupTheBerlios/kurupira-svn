/*
 * Copyright (C) by The Freecolony Project.
 * Please refer to the COPYRIGHT file distributed with this source
 * distribution.
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
 * @file libless_encryption.h
 * 
 * Headers of the Certificateless Public Key Cryptography encryption module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_ENCRYPTION_H_
	#define _LIBLESS_ENCRYPTION_H_

	#include "libless_types.h"

	/**
	 * Generates a set of system parameters and a master key to be used by
	 * the centralized authority.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] params       - the resulting system parameters
	 * @param[out] master_key   - the resulting master key
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_encryption_setup(libless_t *env, libless_params_t *params,
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
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_encryption_extract(libless_t *env, libless_partial_t *key,
		unsigned char *id, int id_len, libless_master_t master,
		libless_params_t parameters);


	/**
	 * Generates a user secret.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] secret       - the resulting secret
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_encryption_set_secret(libless_t *env, libless_secret_t *secret,
		libless_params_t parameters);

	/**
	 * Generates a user public key from the user secret.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] public_key   - the resulting public key
	 * @param[in] secret        - the user secret
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_encryption_set_public(libless_t *env,
		libless_public_t *public_key, libless_secret_t secret,
		libless_params_t parameters);

	/**
	 * Constructs a private key from the partial private key and the user 
	 * secret.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] private      - the resulting private key
	 * @param[in] secret        - the user secret
	 * @param[in] partial       - the user partial private key
	 * @param[in] parameters    - the system parameters.
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_encryption_set_private(libless_t *env, libless_private_t *private,
		libless_secret_t secret, libless_partial_t partial,
		libless_params_t parameters);

	/**
	 * Encrypts data with the user identifier and public key.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] encrypted    - the resulting cryptogram
	 * @param[in] in            - the data to encrypt
	 * @param[in] in_len        - the number of bytes to encrypt
	 * @param[in] id            - the user identifier
	 * @param[in] id_len        - the length of the identifier in bytes
	 * @param[in] public_key    - the user public key
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_encrypt(libless_t *env, libless_ciphertext_t *encrypted,
		unsigned char *in, int in_len, unsigned char *id, int id_len,
		libless_public_t public_key, libless_params_t parameters);

	/**
	 * Deciphers a cryptogram with the user private key.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] out          - the buffer to store decrypted data
	 * @param[out] out_len      - the number of bytes written on the buffer
	 * @param[in] encrypted     - the cryptogram to decipher
	 * @param[in] private       - the user private key
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_decrypt(libless_t *env, unsigned char *out, int *out_len,
		libless_ciphertext_t encrypted, libless_private_t private,
		libless_params_t parameters);

#endif /* !_LIBLESS_ENCRYPTION_H_ */
