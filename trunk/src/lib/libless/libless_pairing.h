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
 * @file libless_pairing.h 
 * 
 * Interface of the pairing primitive module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_PAIRING_H_
	#define _LIBLESS_PAIRING_H_

	/**
	 * Computes a power of a compressed pairing of two elliptic curve points,
	 * that is, \f$ e(P, Q)^{r} \f$. This is a high-level version of the
	 * function.
	 * 
	 * @param[in,out] env       - the library context
	 * @param[out] e            - the result of the pairing computation
	 * @param[in] point_p       - the first point
	 * @param[in] point_q       - the second point, in the twisted curve
	 * @param[in] exponent      - the power, can be NULL
	 * @param[in] parameters    - the cryptosystem parameters
	 * @param[in] ctx           - the OpenSSL context
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_pairing(libless_t *env, BIGNUM *e, EC_POINT *point_p,
		EC_POINT *point_q, BIGNUM *exponent, libless_params_t parameters,
		BN_CTX *ctx);

	/**
	 * Computes the power of a compressed pairing.
	 * 
	 * @param[in, out] env      - the library context
	 * @param[out] e            - the result of the power computation
	 * @param[in] pairing       - the compressed pairing 
	 * @param[in] parameters    - the cryptosystem parameters
	 * @param[in] exponent      - the power
	 * @param[in] ctx           - the OpenSSL context
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_pairing_power(libless_t *env, BIGNUM *e, BIGNUM *pairing,
		BIGNUM *exponent, libless_params_t parameters, BN_CTX *ctx);

	/**
	 * Computes the product of two compressed pairings.
	 * 
	 * @param[in, out] env      - the library context
	 * @param[out] e1           - the first possible result
	 * @param[out] e2           - the second possible result, can be NULL
	 * @param[in] a             - the first compressed pairing
	 * @param[in] b             - the second compressed pairing 
	 * @param[in] parameters    - the cryptosystem parameters
	 * @param[in] ctx           - the OpenSSL context
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int libless_pairing_multiply(libless_t *env, BIGNUM *e1, BIGNUM *e2,
		BIGNUM *a, BIGNUM *b, libless_params_t parameters, BN_CTX *ctx);

#endif /* !_LIBLESS_PAIRING_H_ */
