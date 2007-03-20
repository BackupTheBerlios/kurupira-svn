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
 * @defgroup libless libless, the cryptographic module
 */

/**
 * @file libless.h
 * 
 * Interface of the Certificateless Public Key Cryptography Module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_H_
	#define _LIBLESS_H_

	#include <liberror.h>

	#include "libless_types.h"

	/**
	 * Constant indicating success.
	 */
	#define LIBLESS_OK		1

	/**
	 * Constant indicating error.
	 */
	#define LIBLESS_ERROR	0

	/**
	 * @name Curve
	 * Chosen elliptic curve.
	 */
	/*@{ */
	/** 
	 * Parameter that descrive the chosen curve \f$ y^2 = x^3-3x+b \bmod{p} \f$ 
	 * with \f$ n=\#E(\mathbb{F}_p) \f$ and a subgroup of points with the prime 
	 * order \f$ r=2^{159}+2^{17}+1 \f$ and cofactor \f$ h \f$. The prime number 
	 * \f$ p \f$ is supposed to be congruent to \f$3 \bmod{4}\f$.
	 */
	#define CURVE_P "DF9BD3ED0034174E54597AA4E2AB033D21C7F6F1AFDD080D4708BC67CA"\
		"C2AED554FE43F3DA7CD547ED458502C46356BB2A76688DDF064094EBE7785EDE2E413F"

	#define CURVE_A "DF9BD3ED0034174E54597AA4E2AB033D21C7F6F1AFDD080D4708BC67CA"\
		"C2AED554FE43F3DA7CD547ED458502C46356BB2A76688DDF064094EBE7785EDE2E413C"

	#define CURVE_B "CFEC8DDB4E226F34828D4F9B30571BB52E14D1611FA34031423862B3AC"\
		"B179102A1C152E860FC993A87999CB6A8539516C04950344270037ABC0905175FD47E"

	#define CURVE_H	"1BF37A7DA00682E9CA8B2F549C556067A4388F10141E2BEC5D2CE78CA6"\
		"EF85DBB48606FEFE400661EDE015EF6"

	#define CURVE_R	"8000000000000000000000000000000000020001"

	#define P_OVER_Q "1BF37A7DA00682E9CA8B2F549C556067A4388F10141E2BEC5D2CE78CA"\
		"6EF85DBF05676CCF69E2C1025BAE4140"
	/*@} */

	/**
	 * @name Twisted curve
	 * Twisted elliptic curve.
	 */
	/*@{ */
	/** 
	 * Parameter that describe the twisted curve \f$ y^2= x^3-3x-b \bmod{p} \f$ 
	 * isomorphic to the chosen curve defined on the quadratic extension of the
	 * prime field.
	 */
	#define TWISTED_A	CURVE_A

	#define TWISTED_B	"-" CURVE_B

	#define TWISTED_P	CURVE_P

	#define TWISTED_H "1BF37A7DA00682E9CA8B2F549C556067A4388F10141E2BEC5D2CE78"\
		"CA6EF85DC2C26E69AEEFC51BE5D95B238A"
	/*@} */

	/**
	 * Size in bits of \f$ p \f$, the characteristic of the prime field.
	 */
	#define P_SIZE_BITS	512

	/**
	 * Size in bytes of \f$ p \f$, the characteristic of the prime field.
	 */
	#define P_SIZE_BYTES	((P_SIZE_BITS >> 3) + (P_SIZE_BITS % 8 ? 1 : 0))

	/**
	 * Size in bits of \f$ r \f$, the order of the subgroup of points.
	 */
	#define R_SIZE_BITS	160

	/**
	 * Size in bytes of \f$ r \f$, the order of the subgroup of points.
	 */
	#define R_SIZE_BYTES	((R_SIZE_BITS >> 3) + (R_SIZE_BITS % 8 ? 1 : 0))

	/**
	 * Type that describes the library environment.
	 */
	typedef error_t libless_t;

	/**
	 * Initializes the library.
	 * 
	 * @param[out] env      - the library context
	 */
	void libless_init(libless_t *env);

	/**
	 * Finalizes the library.
	 * 
	 * @param[in,out] env   - the library context.
	 */
	void libless_clean(libless_t *env);

	/**
	 * Generates a set of system parameters and a master key to be used by
	 * the centralized authority.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] params       - the resulting system parameters
	 * @param[out] master_key   - the resulting master key
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_setup(libless_t *env, libless_params_t * params,
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
	int libless_extract(libless_t *env, libless_partial_t *key, unsigned char *id,
		int id_len, libless_master_t master, libless_params_t parameters);


	/**
	 * Generates a user secret.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] secret       - the resulting secret
	 * @param[in] parameters    - the system parameters
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_set_secret(libless_t *env, libless_secret_t *secret,
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
	int libless_set_public(libless_t *env, libless_public_t *public_key,
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
	int libless_set_private(libless_t *env, libless_private_t *private,
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

#endif /* !_LIBLESS_H_ */
