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
 * @file libless_pairing.c
 * 
 * Implementation of the pairing primitive module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#include <string.h>

#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "libless.h"
#include "libless_quadratic.h"
#include "libless_err.h"
#include "libless_timing.h"

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/**
 * Exponent of the last exponentiation in the Tate Pairing computation
 * (\f$ \frac{p + 1}_{r} \f$).
 */
#define LAST_POWER	P_OVER_Q

/** Computes the power of a unary field element from the lucas sequence
 * laddering algorithm.
 * 
 * @param[in,out] env       - the library context
 * @param[out] r            - the resulting field element
 * @param[in] a             - the basis
 * @param[in] n             - the power
 * @param[in] p             - the prime field order
 * @param[in] mctx          - the OpenSSL Montgomery context
 * @param[in] ctx           - the OpenSSL context
 * @returns  LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
 */
static int lucas_sequence(libless_t *env, BIGNUM *r, BIGNUM *a, BIGNUM *n,
		BIGNUM *p, BN_MONT_CTX *mctx, BN_CTX *ctx);

/**
 * Doubles a point and avaliates the contribution of the doubling using a second
 * point specified by its coordinates.
 * 
 * @param[in,out] env       - the library context
 * @param[out] r            - the resulting point after the doubling
 * @param[out] line         - the line avaliated at the third point
 * @param[in] point         - the point to double
 * @param[in] xq            - the x-coordinate of the second point
 * @param[in] yq            - the y-coordinate of the second point
 * @param[in] group         - the elliptic curve group
 * @param[in] ctx           - the OpenSSL context
 * @returns  LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
 */
static int point_doubling_line(libless_t *env, EC_POINT *r, QUADRATIC *line,
		EC_POINT *point, BIGNUM *xq, BIGNUM *yq, EC_GROUP *group, BN_CTX *ctx);

/**
 * Adds two points and avaliates the contribution of the addition using a third
 * point specified by its coordinates.
 * 
 * @param[in,out] env       - the library context
 * @param[out] r            - the resulting point after the addition
 * @param[out] line         - the line avaliated at the third point
 * @param[in] a             - the first point to add
 * @param[in] b             - the second point to add
 * @param[in] xq            - the x-coordinate of the third point
 * @param[in] yq            - the y-coordinate of the third point
 * @param[in] group         - the elliptic curve group
 * @param[in] ctx           - the OpenSSL context
 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
 */
static int point_addition_line(libless_t *env, EC_POINT *r, QUADRATIC *line,
		EC_POINT *a, EC_POINT *b, BIGNUM *xq, BIGNUM *yq, EC_GROUP *group,
		BN_CTX *ctx);

/**
 * Computes a power of a compressed pairing of two elliptic curve points, that
 * is, \f$ e(P, Q)^{r} \f$. This is a high-level version of the function.
 * 
 * @param[in,out] env       - the library context
 * @param[out] e            - the result of the pairing computation
 * @param[in] p             - the first point
 * @param[in] xq            - the x-coordinate of the second point
 * @param[in] yq            - the y-coordinate of the second point
 * @param[in] r             - the power, can be NULL
 * @param[in] group         - the elliptic curve group
 * @param[in] factor        - the factor of the ellyptic curve group order
 * @param[in] ctx           - the OpenSSL context
 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
 */
static int tate_pairing_power(libless_t *env, BIGNUM *e, EC_POINT *p,
		BIGNUM *xq, BIGNUM *yq, BIGNUM *r, EC_GROUP *group, BIGNUM *factor,
		BN_CTX *ctx);

/**
 * Expands the compressed pairing to a quadratic extension element.
 * 
 * @param[in, out] env      - the library context
 * @param[out] e1           - the first possible expanded pairing
 * @param[out] e2           - the second possible expanded pairing, can be NULL
 * @param[in] pairing       - the pairing to expand
 * @param[in] parameters    - the cryptosystem parameters
 * @param[in] ctx           - the OpenSSL context
 * @returns LIBLESS_OK if no error occurs, LIBLESS_ERROR otherwise.
 */
int pairing_expand(libless_t *env, QUADRATIC *e1, QUADRATIC *e2,
		BIGNUM *pairing, libless_params_t parameters, BN_CTX *ctx);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int libless_pairing(libless_t *env, BIGNUM *e, EC_POINT *p, EC_POINT *q,
		BIGNUM *exponent, libless_params_t parameters, BN_CTX *ctx) {
	BIGNUM *xq = NULL;
	BIGNUM *yq = NULL;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);
	TRY(xq = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(yq = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	TRY(EC_POINT_get_affine_coordinates_GFp(parameters.group2, q, xq, yq, ctx),
			ERR(REASON_OPENSSL));

	TRY(tate_pairing_power(env, e, p, xq, yq, exponent, parameters.group1,
					parameters.factor, ctx), ERR(REASON_PAIRING));

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	return code;
}

int libless_pairing_power(libless_t *env, BIGNUM *e, BIGNUM *pairing,
		BIGNUM *exponent, libless_params_t parameters, BN_CTX *ctx) {
	BIGNUM *r = NULL;
	BIGNUM *two = NULL;
	BIGNUM *prime = NULL;
	BN_MONT_CTX *mctx = NULL;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);
	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(two = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(mctx = BN_MONT_CTX_new(), ERR(REASON_MEMORY));

	TRY(BN_set_word(two, 2), ERR(REASON_OPENSSL));

	prime = parameters.prime;

	TRY(BN_MONT_CTX_set(mctx, prime, ctx), ERR(REASON_OPENSSL));

	TRY(BN_to_montgomery(r, pairing, mctx, ctx), ERR(REASON_OPENSSL));

	/* Compute Vm(2a). */
	TRY(BN_mod_lshift1_quick(r, r, prime), ERR(REASON_OPENSSL));

	TRY(lucas_sequence(env, e, r, exponent, prime, mctx, ctx),
			ERR(REASON_LUCAS));

	TRY(BN_from_montgomery(e, e, mctx, ctx), ERR(REASON_OPENSSL));

	/* Compute e = e/2. */
	TRY(BN_mod_inverse(two, two, prime, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul(e, two, e, prime, ctx), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;

end:
	BN_CTX_end(ctx);
	BN_MONT_CTX_free(mctx);
	return code;
}

int libless_pairing_multiply(libless_t *env, BIGNUM *e1, BIGNUM *e2,
		BIGNUM *a, BIGNUM *b, libless_params_t parameters, BN_CTX *ctx) {
	QUADRATIC *qa1 = NULL;
	QUADRATIC *qa2 = NULL;
	QUADRATIC *qb = NULL;
	QUADRATIC *t1 = NULL;
	QUADRATIC *t2 = NULL;
	BIGNUM *t3 = NULL;
	BIGNUM *t4 = NULL;
	BIGNUM *prime = NULL;
	BIGNUM *r = NULL;
	int code;

	code = LIBLESS_ERROR;
	
	BN_CTX_start(ctx);
	TRY(qa1 = QD_new(), ERR(REASON_MEMORY));
	TRY(qa2 = QD_new(), ERR(REASON_MEMORY));
	TRY(qb = QD_new(), ERR(REASON_MEMORY));
	TRY(t1 = QD_new(), goto end);
	TRY(t2 = QD_new(), goto end);
	TRY(t3 = BN_CTX_get(ctx), goto end);
	TRY(t4 = BN_CTX_get(ctx), goto end);
	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	TRY(pairing_expand(env, qa1, qa2, a, parameters, ctx),
			ERR(REASON_EXPANSION));
	TRY(pairing_expand(env, qb, NULL, b, parameters, ctx),
			ERR(REASON_EXPANSION));

	prime = parameters.prime;

	TRY(BN_mod_mul(r, qa1->x, qb->x, prime, ctx), ERR(REASON_OPENSSL));

	TRY(BN_mod_mul(e1, qa1->y, qb->y, prime, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(e1, r, e1, prime), ERR(REASON_OPENSSL));

	if (e2 != NULL) {
		TRY(BN_mod_mul(e2, qa2->y, qb->y, prime, ctx), ERR(REASON_OPENSSL));
		TRY(BN_mod_sub_quick(e2, r, e2, prime), ERR(REASON_OPENSSL));
	}

	code = LIBLESS_OK;
end:
	QD_free(qa1);
	QD_free(qa2);
	QD_free(qb);
	QD_free(t1);
	QD_free(t2);
	BN_CTX_end(ctx);
	return code;
}


/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

static int lucas_sequence(libless_t *env, BIGNUM *r, BIGNUM *a, BIGNUM *n,
		BIGNUM *p, BN_MONT_CTX *mctx, BN_CTX *ctx) {
	BIGNUM *t0 = NULL;
	BIGNUM *t1 = NULL;
	BIGNUM *t2 = NULL;
	int i;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);
	TRY(t0 = BN_CTX_get(ctx), ERR(REASON_OPENSSL));
	TRY(t1 = BN_CTX_get(ctx), ERR(REASON_OPENSSL));
	TRY(t2 = BN_CTX_get(ctx), ERR(REASON_OPENSSL));

	TRY(BN_set_word(t0, 2), ERR(REASON_OPENSSL));
	TRY(BN_copy(t1, a), ERR(REASON_OPENSSL));
	TRY(BN_set_word(t2, 2), ERR(REASON_OPENSSL));
	BN_to_montgomery(t0, t0, mctx, ctx);
	BN_to_montgomery(t2, t2, mctx, ctx);

	for (i = BN_num_bits(n) - 1; i >= 0; i--) {
		if (BN_is_bit_set(n, i)) {
			TRY(BN_mod_mul_montgomery(t0, t0, t1, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_sub_quick(t0, t0, a, p), ERR(REASON_OPENSSL));
			TRY(BN_mod_mul_montgomery(t1, t1, t1, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_sub_quick(t1, t1, t2, p), ERR(REASON_OPENSSL));
		} else {
			TRY(BN_mod_mul_montgomery(t1, t0, t1, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_sub_quick(t1, t1, a, p), ERR(REASON_OPENSSL));
			TRY(BN_mod_mul_montgomery(t0, t0, t0, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_sub_quick(t0, t0, t2, p), ERR(REASON_OPENSSL));
		}
	}
	TRY(BN_copy(r, t0), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	return code;
}

static int point_doubling_line(libless_t *env, EC_POINT *r, QUADRATIC *line,
		EC_POINT *point, BIGNUM *xq, BIGNUM *yq, EC_GROUP *group, BN_CTX *ctx) {
	BIGNUM *xp = NULL;
	BIGNUM *yp = NULL;
	BIGNUM *zp = NULL;
	BIGNUM *xr = NULL;
	BIGNUM *yr = NULL;
	BIGNUM *zr = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *t0 = NULL;
	BIGNUM *t1 = NULL;
	BIGNUM *t2 = NULL;
	BIGNUM *t3 = NULL;
	BIGNUM *t4 = NULL;
	BN_MONT_CTX *mctx = NULL;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);

	TRY(xp = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(yp = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(zp = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(xr = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(yr = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(zr = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(p = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(a = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t0 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t1 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t2 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t3 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t4 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(mctx = BN_MONT_CTX_new(), ERR(REASON_MEMORY));

	/* Get the points' coordinates. */
	TRY(EC_POINT_get_Jprojective_coordinates_GFp
			(group, point, xp, yp, zp, ctx), ERR(REASON_OPENSSL));

	/* Test the point. */
	if (BN_is_zero(yp)) {
		ERR(REASON_POINT_INFINITY);
	}

	/* Get the prime field order. */
	TRY(EC_GROUP_get_curve_GFp(group, p, a, NULL, ctx), ERR(REASON_OPENSSL));

	/* Initialize Montgomery arithmetic. */
	TRY(BN_MONT_CTX_set(mctx, p, ctx), ERR(REASON_OPENSSL));

	if (BN_is_one(zp)) {
		/* Compute t1 = 3 * xp^2 + a. */
		TRY(BN_mod_mul_montgomery(t4, zp, zp, mctx, ctx), ERR(REASON_OPENSSL));
		TRY(BN_mod_mul_montgomery(t0, xp, xp, mctx, ctx), ERR(REASON_OPENSSL));
		TRY(BN_mod_lshift1_quick(t1, t0, p), ERR(REASON_OPENSSL));
		TRY(BN_mod_add_quick(t0, t0, t1, p), ERR(REASON_OPENSSL));
		TRY(BN_mod_add_quick(t1, t0, a, p), ERR(REASON_OPENSSL));
	} else {
		/* Compute t0 = -3 (mod p). */
		TRY(BN_copy(t0, p), ERR(REASON_OPENSSL));
		TRY(BN_sub_word(t0, 3), ERR(REASON_OPENSSL));

		if (BN_cmp(a, t0) == 0) {
			/* Compute t4 = zp^2 and
			 * t1 = 3 * (xp + zp^2) * (xp - zp^2) = 3 * xp^2 - 3 * zp^4. */
			TRY(BN_mod_mul_montgomery(t4, zp, zp, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_add_quick(t0, xp, t4, p), ERR(REASON_OPENSSL));
			TRY(BN_mod_sub_quick(t2, xp, t4, p), ERR(REASON_OPENSSL));
			TRY(BN_mod_mul_montgomery(t1, t0, t2, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_lshift1_quick(t0, t1, p), ERR(REASON_OPENSSL));
			TRY(BN_mod_add_quick(t1, t0, t1, p), ERR(REASON_OPENSSL));
		} else {
			/* Compute t4 = zp^2, t1 = 3 * xp^2 + a * zp^4. */
			TRY(BN_to_montgomery(a, a, mctx, ctx), ERR(REASON_OPENSSL));
			TRY(BN_mod_mul_montgomery(t0, xp, xp, mctx, ctx),
					ERR(REASON_OPENSSL));

			TRY(BN_mod_lshift1_quick(t1, t0, p), ERR(REASON_OPENSSL));

			TRY(BN_mod_add_quick(t0, t0, t1, p), ERR(REASON_OPENSSL));
			TRY(BN_mod_mul_montgomery(t4, zp, zp, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_mul_montgomery(t1, t4, t4, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_mul_montgomery(t1, t1, a, mctx, ctx),
					ERR(REASON_OPENSSL));
			TRY(BN_mod_add_quick(t1, t1, t0, p), ERR(REASON_OPENSSL));
		}
	}
	/* Compute zr = 2 * yp * zp. */
	if (BN_is_one(zp)) {
		TRY(BN_copy(t0, yp), ERR(REASON_OPENSSL));
	} else {
		TRY(BN_mod_mul_montgomery(t0, yp, zp, mctx, ctx), ERR(REASON_OPENSSL));
	}
	TRY(BN_mod_lshift1_quick(zr, t0, p), ERR(REASON_OPENSSL));

	/* Compute t3 = yp^2, t2 = 4 * xp * yp^2. */
	TRY(BN_mod_mul_montgomery(t3, yp, yp, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(t2, xp, t3, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_lshift_quick(t2, t2, 2, p), ERR(REASON_OPENSSL));

	/* Compute xr = t1^2 - 2 * t2. */
	TRY(BN_mod_lshift1_quick(t0, t2, p), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(xr, t1, t1, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(xr, xr, t0, p), ERR(REASON_OPENSSL));


	/* Compute t0 = 8 * yp^4. */
	TRY(BN_mod_mul_montgomery(t0, t3, t3, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_lshift_quick(t0, t0, 3, p), ERR(REASON_OPENSSL));

	/* Compute yr = t1 * (t2 - xr) - t0. */
	TRY(BN_mod_sub_quick(yr, t2, xr, p), ERR(REASON_OPENSSL));

	TRY(BN_mod_mul_montgomery(yr, t1, yr, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(yr, yr, t0, p), ERR(REASON_OPENSSL));

	/* Now, the slope is stored on t1/zr. */

	/* Compute line_x = t1 * (zp^2 * xq + xp) - 2*yp^2. */
	TRY(BN_mod_mul_montgomery(t0, t4, xq, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_add_quick(t0, t0, xp, p), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(line->x, t1, t0, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_lshift1_quick(t0, t3, p), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(line->x, line->x, t0, p), ERR(REASON_OPENSSL));

	/* Compute line_y = yq * zp^2 * zr. */
	TRY(BN_mod_mul_montgomery(line->y, yq, zr, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(line->y, line->y, t4, mctx, ctx),
			ERR(REASON_OPENSSL));

	/* Set the resulting point coordinates. */
	TRY(EC_POINT_set_Jprojective_coordinates_GFp(group, r, xr, yr, zr, ctx),
			ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_MONT_CTX_free(mctx);
	return code;
}

static int point_addition_line(libless_t *env, EC_POINT *r, QUADRATIC *line,
		EC_POINT *a, EC_POINT *b, BIGNUM *xq, BIGNUM *yq, EC_GROUP *group,
		BN_CTX *ctx) {
	BIGNUM *xa = NULL;
	BIGNUM *ya = NULL;
	BIGNUM *za = NULL;
	BIGNUM *xb = NULL;
	BIGNUM *yb = NULL;
	BIGNUM *zb = NULL;
	BIGNUM *xr = NULL;
	BIGNUM *yr = NULL;
	BIGNUM *zr = NULL;
	BIGNUM *p = NULL;
	BIGNUM *t0 = NULL;
	BIGNUM *t1 = NULL;
	BIGNUM *t2 = NULL;
	BIGNUM *t3 = NULL;
	BIGNUM *t4 = NULL;
	BIGNUM *t5 = NULL;
	BIGNUM *t6 = NULL;
	BIGNUM *z3 = NULL;
	BN_MONT_CTX *mctx = NULL;
	int code;
	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);

	TRY(xa = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(ya = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(za = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(xb = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(yb = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(zb = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(xr = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(yr = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(zr = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(p = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t0 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t1 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t2 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t3 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t4 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t5 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(t6 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(z3 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(mctx = BN_MONT_CTX_new(), ERR(REASON_MEMORY));

	/* Get the points' coordinates. */
	TRY(EC_POINT_get_Jprojective_coordinates_GFp(group, a, xa, ya, za, ctx),
			ERR(REASON_OPENSSL));
	TRY(EC_POINT_get_Jprojective_coordinates_GFp(group, b, xb, yb, zb, ctx),
			ERR(REASON_OPENSSL));

	/* Get the prime field order. */
	TRY(EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx), ERR(REASON_OPENSSL));

	/* Initialize Montgomery arithmetic. */
	TRY(BN_MONT_CTX_set(mctx, p, ctx), ERR(REASON_OPENSSL));

	/* Convert to Montgomery form. */
	TRY(BN_to_montgomery(xb, xb, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(yb, yb, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(zb, zb, mctx, ctx), ERR(REASON_OPENSSL));

	if (BN_is_one(zb)) {
		/* Make t1 = xa, t2 = ya. */
		TRY(BN_copy(t1, xa), ERR(REASON_OPENSSL));
		TRY(BN_copy(t2, ya), ERR(REASON_OPENSSL));
	} else {
		/* Compute t1 = xa * zb^2. */
		TRY(BN_mod_mul_montgomery(t0, zb, zb, mctx, ctx), ERR(REASON_OPENSSL));
		TRY(BN_mod_mul_montgomery(t1, xa, t0, mctx, ctx), ERR(REASON_OPENSSL));
		/* Compute t2 = ya * zb^3. */
		TRY(BN_mod_mul_montgomery(t0, t0, zb, mctx, ctx), ERR(REASON_OPENSSL));
		TRY(BN_mod_mul_montgomery(t2, ya, t0, mctx, ctx), ERR(REASON_OPENSSL));
	}

	if (BN_is_one(za)) {
		/* Make t3 = xb and t4 = yb. */
		TRY(BN_copy(t3, xb), ERR(REASON_OPENSSL));
		TRY(BN_copy(t4, yb), ERR(REASON_OPENSSL));
	} else {
		/* Compute t3 = xb * za^2. */
		TRY(BN_mod_mul_montgomery(z3, za, za, mctx, ctx), ERR(REASON_OPENSSL));
		TRY(BN_mod_mul_montgomery(t3, xb, z3, mctx, ctx), ERR(REASON_OPENSSL));
		/* Compute t4 = yb * za^3. */
		TRY(BN_mod_mul_montgomery(z3, z3, za, mctx, ctx), ERR(REASON_OPENSSL));
		TRY(BN_mod_mul_montgomery(t4, yb, z3, mctx, ctx), ERR(REASON_OPENSSL));
	}

	/* Compute t5 = t1 - t3 and t6 = t2 - t4. */
	TRY(BN_mod_sub_quick(t5, t1, t3, p), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(t6, t2, t4, p), ERR(REASON_OPENSSL));

	/* Test the points. */
	if (BN_is_zero(t5)) {
		if (BN_is_zero(t6)) {
			/* Point A = Point B. */
			BN_CTX_end(ctx);
			return point_doubling_line(env, r, line, a, xq, yq, group, ctx);
		} else {
			/* Point at infinity. */
			ERR(REASON_POINT_INFINITY);
		}
	}

	/* Compute t1 (t7) = t1 + t3 and t2 (t8) = t2 + t4. */
	TRY(BN_mod_add_quick(t1, t1, t3, p), ERR(REASON_OPENSSL));
	TRY(BN_mod_add_quick(t2, t2, t4, p), ERR(REASON_OPENSSL));

	if (BN_is_one(za) && BN_is_one(zb)) {
		/* Make zr = t5. */
		TRY(BN_copy(zr, t5), ERR(REASON_OPENSSL));
	} else {
		if (BN_is_one(za)) {
			/* Make t0 = zb. */
			TRY(BN_copy(t0, zb), ERR(REASON_OPENSSL));
		} else {
			if (BN_is_one(zb)) {
				/* Make t0 = za. */
				TRY(BN_copy(t0, za), ERR(REASON_OPENSSL));
			} else {
				/* Compute t0 = za * zb. */
				TRY(BN_mod_mul_montgomery(t0, za, zb, mctx, ctx),
						ERR(REASON_OPENSSL));
			}
		}
		/* Make zr = t0 * t5. */
		TRY(BN_mod_mul_montgomery(zr, t0, t5, mctx, ctx), ERR(REASON_OPENSSL));
	}

	/* Compute xr = t6^2 - t5^2 * t7. */
	TRY(BN_mod_mul_montgomery(t0, t6, t6, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(t4, t5, t5, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(t3, t1, t4, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(xr, t0, t3, p), ERR(REASON_OPENSSL));

	/* Compute t0 (t9) = t5^2 * t7 - 2 * xr. */
	TRY(BN_mod_lshift1_quick(t0, xr, p), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(t0, t3, t0, p), ERR(REASON_OPENSSL));

	/* Compute yr = (t6 * t9 - t8 * t5^3)/2. */
	TRY(BN_mod_mul_montgomery(t0, t0, t6, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(t5, t4, t5, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(t1, t2, t5, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(t0, t0, t1, p), ERR(REASON_OPENSSL));
	if (BN_is_odd(t0)) {
		TRY(BN_add(t0, t0, p), ERR(REASON_OPENSSL));
	}
	TRY(BN_rshift1(yr, t0), ERR(REASON_OPENSSL));

	/* Now, the slope is stored on t6/zr. */

	/* Compute t0 = t6 * (za^3 * xq + za * xa). */
	TRY(BN_mod_mul_montgomery(t0, za, xa, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(t1, z3, xq, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_add_quick(t0, t1, t0, p), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(t0, t6, t0, mctx, ctx), ERR(REASON_OPENSSL));

	/* Compute line_x = t0 - ya * zr. */
	TRY(BN_mod_mul_montgomery(t1, ya, zr, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(line->x, t0, t1, p), ERR(REASON_OPENSSL));

	/* Compute line_y = yq * zr * za^3. */
	TRY(BN_mod_mul_montgomery(line->y, yq, zr, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul_montgomery(line->y, line->y, z3, mctx, ctx),
			ERR(REASON_OPENSSL));

	/* Set the resulting point coordinates. */
	TRY(EC_POINT_set_Jprojective_coordinates_GFp(group, r, xr, yr, zr, ctx),
			ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_MONT_CTX_free(mctx);
	return code;
}

static int tate_pairing_power(libless_t *env, BIGNUM *e, EC_POINT *p,
		BIGNUM *xq, BIGNUM *yq, BIGNUM *r, EC_GROUP *group, BIGNUM *factor,
		BN_CTX *ctx) {
	EC_POINT *point = NULL;
	QUADRATIC *result = NULL;
	QUADRATIC *line = NULL;
	QUADRATIC *inv = NULL;
	BIGNUM *two = NULL;
	BIGNUM *prime = NULL;
	BIGNUM *power = NULL;
	BIGNUM *xp = NULL;
	BIGNUM *yp = NULL;
	BIGNUM *zp = NULL;
	BN_MONT_CTX *mctx = NULL;
	int i;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);

	TRY(point = EC_POINT_dup(p, group), ERR(REASON_OPENSSL));
	TRY(result = QD_new(), ERR(REASON_OPENSSL));
	TRY(line = QD_new(), ERR(REASON_OPENSSL));
	TRY(inv = QD_new(), ERR(REASON_MEMORY));
	TRY(two = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(power = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(prime = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(xp = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(yp = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(zp = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(mctx = BN_MONT_CTX_new(), ERR(REASON_MEMORY));

	TRY(BN_set_word(two, 2), ERR(REASON_OPENSSL));
	TRY(BN_set_word(result->x, 1), ERR(REASON_OPENSSL));
	TRY(BN_zero(result->y), ERR(REASON_OPENSSL));

	TRY(EC_GROUP_get_curve_GFp(group, prime, NULL, NULL, ctx),
			ERR(REASON_CURVE_PARAMETERS));

	/* Initialize Montgomery arithmetic. */
	TRY(BN_MONT_CTX_set(mctx, prime, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(xq, xq, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(yq, yq, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(result->x, result->x, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(result->y, result->y, mctx, ctx), ERR(REASON_OPENSSL));

	/* Convert point to Montgomery form. */
	TRY(EC_POINT_get_Jprojective_coordinates_GFp
			(group, point, xp, yp, zp, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(xp, xp, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(yp, yp, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(BN_to_montgomery(zp, zp, mctx, ctx), ERR(REASON_OPENSSL));
	TRY(EC_POINT_set_Jprojective_coordinates_GFp
			(group, point, xp, yp, zp, ctx), ERR(REASON_OPENSSL));

	/* Miller algorithm. */
	for (i = BN_num_bits(factor) - 2; i >= 0; i--) {
		TRY(QD_sqr(result, result, prime, mctx, ctx), ERR(REASON_QUADRATIC));
		TRY(point_doubling_line(env, point, line, point, xq, yq, group, ctx),
				ERR(REASON_DOUBLING));
		TRY(QD_mul(result, result, line, prime, mctx, ctx),
				ERR(REASON_QUADRATIC));
		if (BN_is_bit_set(factor, i) && i > 0) {
			TRY(point_addition_line(env, point, line, point, p, xq,
							yq, group, ctx), ERR(REASON_ADDITION));
			TRY(QD_mul(result, result, line, prime, mctx, ctx),
					ERR(REASON_QUADRATIC));
		}

		if (QD_is_zero(result)) {
			ERR(REASON_QUADRATIC);
		}
	}

	/* We do not need the last distance accumulation because this value
	 * does not interfere in the pairing result at all. */

	/* Compute inv = result^(-1). */
	TRY(QD_inv(inv, result, prime, mctx, ctx), ERR(REASON_QUADRATIC));

	/* result = conj(result). */
	TRY(QD_conj(result, result, prime, ctx), ERR(REASON_QUADRATIC));

	/* result = conj(result) * result^(-1). */
	TRY(QD_mul(result, result, inv, prime, mctx, ctx), ERR(REASON_QUADRATIC));

	TRY(BN_mod_lshift1_quick(e, result->x, prime), ERR(REASON_OPENSSL));

	TRY(BN_hex2bn(&power, LAST_POWER), ERR(REASON_CURVE_PARAMETERS));

	TRY(lucas_sequence(env, e, e, power, prime, mctx, ctx), ERR(REASON_LUCAS));

	if (r != NULL) {
		TRY(lucas_sequence(env, e, e, r, prime, mctx, ctx), ERR(REASON_LUCAS));
	}

	TRY(BN_from_montgomery(e, e, mctx, ctx), ERR(REASON_OPENSSL));

	/* Compute e = e/2. */
	TRY(BN_mod_inverse(two, two, prime, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_mul(e, two, e, prime, ctx), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	EC_POINT_free(point);
	BN_CTX_end(ctx);
	BN_MONT_CTX_free(mctx);
	QD_free(result);
	QD_free(line);
	QD_free(inv);
	return code;
}

int pairing_expand(libless_t *env, QUADRATIC *e1, QUADRATIC *e2,
		BIGNUM *pairing, libless_params_t parameters, BN_CTX *ctx) {
	BIGNUM *prime = NULL;
	BIGNUM *p = NULL;
	BIGNUM *one = NULL;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);
	TRY(p = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(one = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	/* Get the prime field order. */
	prime = parameters.prime;

	TRY(BN_set_word(one, 1), ERR(REASON_OPENSSL));

	/* Compute (p + 1)/4. */
	TRY(BN_add(p, prime, one), ERR(REASON_OPENSSL));
	TRY(BN_rshift(p, p, 2), ERR(REASON_OPENSSL));

	/* Compute sqrt(1 - a^2) = (1 - a^2)^((p+1)/4). */
	TRY(BN_mod_sqr(e1->y, pairing, prime, ctx), ERR(REASON_OPENSSL));
	TRY(BN_mod_sub_quick(e1->y, one, e1->y, prime), ERR(REASON_OPENSSL));
	TRY(BN_mod_exp_mont(e1->y, e1->y, p, prime, ctx, NULL), ERR(REASON_OPENSSL));

	TRY(BN_copy(e1->x, pairing), ERR(REASON_OPENSSL));

	if (e2 != NULL) {
		/* Make e2 = (e2->x, -e1->y). */
		TRY(BN_copy(e2->x, e1->x), ERR(REASON_OPENSSL));
		TRY(BN_mod_sub_quick(e2->y, prime, e1->y, prime), ERR(REASON_OPENSSL));
	}

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	return code;
}
