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
 * @file libless_util.h
 * 
 * Hash functions and cipher headers.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_UTIL_H_
	#define _LIBLESS_UTIL_H_

	/**
	 * Flag to tell cipher function to encrypt.
	 */
	#define CIPHER_ENCRYPT			1

	/**
	 * Flag to tell cipher function to decrypt
	 */
	#define CIPHER_DECRYPT			0

	/**
	 * Length in bytes of the cipher block.
	 */
	#define CIPHER_LENGTH			16
	
	/**
	 * Length in bytes of the key used by the cipher function.
	 */
	#define CIPHER_KEY_LENGTH		16

	/**
	 * Length in bytes of the digest value returned by the hash function.
	 */
	#define HASH_LENGTH				20

	/**
	 * Encrypts an arbitrary byte vector. The output buffer must have enough 
	 * capacity to hold the input buffer plus CIPHER_LENGTH and the
	 * key buffer must have CIPHER_KEY_LENGTH bytes.
	 * 
	 * @param[in,out] env   - the library context
	 * @param[out] out      - the resulting encrypted data
	 * @param[out] out_len  - the number of bytes written on the output buffer
	 * @param[in] in        - the data to encrypt
	 * @param[in] in_len    - length of plaintext data in bytes
	 * @param[in] key       - key byte vector
	 * @param[in] enc       - 1 to encrypt, 0 to decrypt
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_cipher(libless_t *env, unsigned char *out, int *out_len,
		unsigned char *in, int in_len, unsigned char *key, int enc);

	/**
	 * Hashes an arbitrary byte vector to a point on the curve. The function
	 * implements the transformation defined in IBCS#1 to map strings to
	 * elliptic curve points. A valid OpenSSL context must be passed to the
	 * function to optimize memory allocation.
	 * 
	 * @param[in,out] env   - the library context
	 * @param[out] point    - the resulting point
	 * @param[in] in        - the byte vector
	 * @param[in] in_len    - the byte vector length in bytes
	 * @param[in] group   - the group of points on the curve
	 * @param[in] ctx       - the OpenSSL context
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_hash_to_point(libless_t *env, EC_POINT *point, unsigned char *in,
		int in_len, EC_GROUP *group, BN_CTX *ctx);

	/**
	 * Hashes an arbitrary byte vector. The output buffer must have HASH_LENGTH
	 * bytes.
	 * 
	 * @param[in,out] env   - the library context
	 * @param[out] out      - the resulting hash value
	 * @param[in] in        - the data to be hashed
	 * @param[in] in_len    - length of data in bytes
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */

	int libless_hash(libless_t *env, unsigned char *out, unsigned char *in,
		int in_len);

	/**
	 * Hashes an arbitrary byte vector to a integer modulo p. The function
	 * computes iterated hash functions of the byte vector. The hash function
	 * used is the SHA1 function, as defined in IBCS#1. A valid OpenSSL context
	 * is passed to the function to optimize memory allocation.
	 * 
	 * @param[in,out] env   - the library context
	 * @param[out] number   - the resulting integer modulo p
	 * @param[in] in        - the byte vector
	 * @param[in] in_len    - the byte vector length in bytes
	 * @param[in] p         - the modulus
	 * @returns LIBLESS_OK if successful, LIBLESS_ERROR otherwise.
	 */
	int libless_hash_to_integer(libless_t *env, BIGNUM *number,
		unsigned char *id, int id_len, BIGNUM *p);

#endif /* !_LIBLESS_UTIL_H_ */
