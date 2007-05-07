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
 * @file libless_quadratic.h
 * 
 * Interface of the quadratic extension field arithmetic module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_QUADRATIC_H_
	#define _LIBLESS_QUADRATIC_H_
	
	#include <openssl/bn.h>

	/**
	 * Type that stores a element of a quadratic extension of a finite field.
	 */
	typedef struct {
		BIGNUM *x; /**< The first component of the element. */
		BIGNUM *y; /**< The second component of the element. */
	} QUADRATIC;

	/**
	 * Allocates and initializes a quadratic extension element.
	 * 
	 * @returns A quadratic extension element if no error occurs, NULL otherwise.
	 */
	QUADRATIC *QD_new();
	
	/**
	 * Duplicates a quadratic extension element.
	 * 
	 * @param a				- the element to duplicate
	 * @returns A quadratic extension element if no error occurs, NULL otherwise.
	 */
	 QUADRATIC *QD_dup(QUADRATIC *a);

	/**
	 * Computes the square of a quadratic extension element.
	 * 
	 * @param[out] r        - the resulting quadratic extension element
	 * @param[in] a         - the quadratic extension element to square
	 * @param[in] p         - the prime order of the field
	 * @param[in] mctx		- the OpenSSL Montgomery context
	 * @param[in] ctx       - the OpenSSL context
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int QD_sqr(QUADRATIC *r, QUADRATIC *a, BIGNUM *p, BN_MONT_CTX *mctx,
		BN_CTX *ctx);

	/**
	 * Multiplies two quadratic extension elements.
	 * 
	 * @param[out] r        - the resulting quadratic extension element
	 * @param[in] a         - the first quadratic extension element to multiply
	 * @param[in] b         - the second quadratic extension element to multiply
	 * @param[in] p         - the prime order of the field
	 * @param[in] mctx		- the OpenSSL Montgomery context
	 * @param[in] ctx       - the OpenSSL context
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int QD_mul(QUADRATIC *r, QUADRATIC *a, QUADRATIC *b, BIGNUM *p,
		BN_MONT_CTX *mctx, BN_CTX *ctx);

	/**
	 * Computes the conjugate of a quadratic extension element.
	 * 
	 * @param[out] r        - the resulting quadratic extension element
	 * @param[in] a         - the quadratic element to compute the conjugate
	 * @param[in] p         - the prime field order
	 * @param[in] ctx       - the OpenSSL context
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int QD_conj(QUADRATIC *r, QUADRATIC *a, BIGNUM *p, BN_CTX *ctx);

	/**
	 * Computes the inverse of a quadratic extension element.
	 * 
	 * @param[out] r        - the resulting quadratic extension element
	 * @param[in] a         - the quadratic extension element to invert
	 * @param[in] p         - the prime field order
	 * @param[in] mctx      - the OpenSSL Montgomery context
	 * @param[in] ctx       - the OpenSSL context
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int QD_inv(QUADRATIC *r, QUADRATIC *a, BIGNUM *p, BN_MONT_CTX *mctx,
		BN_CTX *ctx);

	/**
	 * Tests if the quadratic extension element equals zero.
	 * 
	 * @param[in] a         - the quadratic extension element to test
	 * @returns 1 if the condition is true, 0 otherwise.
	 */
	int QD_is_zero(QUADRATIC *a);

	/**
	 * Copies one quadratic extension field to another.
	 * 
	 * @param[out] to		- the destination
	 * @param[in] from		- the source
	 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
	 */
	int QD_copy(QUADRATIC *to, QUADRATIC *from);

	/**
	 * Compares two quadratic extension elements for equality.
	 * 
	 * @param[in] a			- the first quadratic extension element
	 * @param[in] b			- the second quadratic extension element
	 * @returns 1 if the elements are equal, 0 otherwise
	 */
	int QD_equal(QUADRATIC *a, QUADRATIC *b);

	/**
	 * Frees the memory allocated to the quadratic extension element.
	 * 
	 * @param[in, out] a    - the quadratic extension element to free.
	 */
	void QD_free(QUADRATIC *a);

#endif /* !_LIBLESS_QUADRATIC_H_ */
