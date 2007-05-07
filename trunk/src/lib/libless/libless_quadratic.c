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
 * @file libless_quadratic.c
 * 
 * Implementation of the quadratic extension field arithmetic module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#include <stdlib.h>

#include "libless.h"
#include "libless_quadratic.h"
#include "libless_error.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

QUADRATIC *QD_new() {
	QUADRATIC *a = NULL;
	int code;

	code = LIBLESS_ERROR;

	TRY(a = (QUADRATIC *)malloc(sizeof(QUADRATIC)), return NULL);
	TRY(a->x = BN_new(), goto end);
	TRY(a->y = BN_new(), goto end);

	code = LIBLESS_OK;
end:
	if (code != LIBLESS_OK) {
		QD_free(a);
		a = NULL;
	}
	return a;
}

QUADRATIC *QD_dup(QUADRATIC *a) {
	QUADRATIC *b = NULL;
	int code;

	code = LIBLESS_ERROR;

	TRY(b = (QUADRATIC *)malloc(sizeof(QUADRATIC)), return NULL);
	TRY(b->x = BN_dup(a->x), goto end);
	TRY(b->y = BN_dup(a->y), goto end);

	code = LIBLESS_OK;
end:
	if (code != LIBLESS_OK) {
		QD_free(b);
		b = NULL;
	}
	return b;
}

int QD_sqr(QUADRATIC *r, QUADRATIC *a, BIGNUM *p, BN_MONT_CTX *mctx,
		BN_CTX *ctx) {
	BIGNUM *t1 = NULL;
	BIGNUM *t2 = NULL;
	int code;

	code = LIBLESS_ERROR;

	TRY(t1 = BN_dup(a->x), goto end);
	TRY(t2 = BN_dup(a->x), goto end);

	/* Compute t1 = (a_x + a_y). */
	TRY(BN_mod_add_quick(t1, t1, a->y, p), goto end);

	/* Compute t2 = (a_x - a_y). */
	TRY(BN_mod_sub_quick(t2, t2, a->y, p), goto end);

	/* Compute r_y = a_x*a_y. */
	TRY(BN_mod_mul_montgomery(r->y, a->x, a->y, mctx, ctx), goto end);

	/* Compute r_x = (a_x + a_y)*(a_x - a_y). */
	TRY(BN_mod_mul_montgomery(r->x, t1, t2, mctx, ctx), goto end);

	/* Compute r_y = 2*a_x*a_y. */
	TRY(BN_mod_lshift1_quick(r->y, r->y, p), goto end);

	code = LIBLESS_OK;
end:
	BN_free(t1);
	BN_free(t2);
	return code;
}

int QD_mul(QUADRATIC *r, QUADRATIC *a, QUADRATIC *b, BIGNUM *p,
		BN_MONT_CTX *mctx, BN_CTX *ctx) {
	BIGNUM *t1 = NULL;
	BIGNUM *t2 = NULL;
	BIGNUM *t3 = NULL;
	int code;

	code = LIBLESS_ERROR;

	if (a == b) {
		return QD_sqr(r, a, p, mctx, ctx);
	}

	TRY(t1 = BN_dup(a->x), goto end);
	TRY(t2 = BN_dup(a->y), goto end);
	TRY(t3 = BN_dup(b->x), goto end);

	/* t1 = a_x*b_x. */
	TRY(BN_mod_mul_montgomery(t1, t1, b->x, mctx, ctx), goto end);

	/* t2 = a_y*b_y. */
	TRY(BN_mod_mul_montgomery(t2, t2, b->y, mctx, ctx), goto end);

	/* t3 = (b_x + b_y). */
	TRY(BN_mod_add_quick(t3, t3, b->y, p), goto end);

	/* r_y = a_x + a_y. */
	TRY(BN_mod_add_quick(r->y, a->x, a->y, p), goto end);

	/* r_y = (a_x + a_y)*(b_x + b_y). */
	TRY(BN_mod_mul_montgomery(r->y, r->y, t3, mctx, ctx), goto end);

	/* r_y = (a_x + a_y)*(b_x + b_y) - (a_x*b_x). */
	TRY(BN_mod_sub_quick(r->y, r->y, t1, p), goto end);

	/* r_y = (a_x + a_y)*(b_x + b_y) - (a_x*b_x) - (a_y*b_y). */
	TRY(BN_mod_sub_quick(r->y, r->y, t2, p), goto end);

	/* r_x = (a_x*b_x - a_y*b_y). */
	TRY(BN_mod_sub_quick(r->x, t1, t2, p), goto end);

	code = LIBLESS_OK;
end:
	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	return code;
}

int QD_conj(QUADRATIC *r, QUADRATIC *a, BIGNUM *p, BN_CTX *ctx) {
	int code;

	code = LIBLESS_ERROR;

	if (a == r) {
		TRY(BN_mod_sub_quick(r->y, p, r->y, p), goto end);
	}
	else {
		TRY(BN_copy(r->x, a->x), goto end);
		TRY(BN_mod_sub_quick(r->y, p, a->y, p), goto end);
	}
	code = LIBLESS_OK;
end:
	return code;
}

int QD_inv(QUADRATIC *r, QUADRATIC *a, BIGNUM *p, BN_MONT_CTX *mctx,
		BN_CTX *ctx) {
	QUADRATIC *t1 = NULL;
	QUADRATIC *t2 = NULL;
	BIGNUM *t3 = NULL;
	BIGNUM *t4 = NULL;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);
	TRY(t1 = QD_new(), goto end);
	TRY(t2 = QD_new(), goto end);
	TRY(t3 = BN_CTX_get(ctx), goto end);
	TRY(t4 = BN_CTX_get(ctx), goto end);

	TRY(QD_conj(t1, a, p, ctx), goto end);

	/* t3 = a_x^2, t4 = a_y^2. */
	TRY(BN_mod_mul_montgomery(t3, a->x, a->x, mctx, ctx), goto end);
	TRY(BN_mod_mul_montgomery(t4, a->y, a->y, mctx, ctx), goto end);

	/* t3 = a_x^2 + a_y^2. */
	TRY(BN_mod_add_quick(t3, t3, t4, p), goto end);

	/* t3 = t3^(-1). */
	TRY(BN_from_montgomery(t3, t3, mctx, ctx), goto end);
	TRY(BN_mod_inverse(t3, t3, p, ctx), goto end);
	TRY(BN_to_montgomery(t3, t3, mctx, ctx), goto end);

	TRY(BN_copy(t2->x, t3), goto end);
	TRY(BN_zero(t2->y), goto end);

	/* If a is in Montgomery form aR mod p, this will compute (aR)^(-1) mod p. */
	TRY(QD_mul(r, t1, t2, p, mctx, ctx), goto end);

	code = LIBLESS_OK;
end:
	QD_free(t1);
	QD_free(t2);
	BN_CTX_end(ctx);
	return code;
}

int QD_is_zero(QUADRATIC *a) {
	return (BN_is_zero(a->x) && BN_is_zero(a->y));
}

int QD_copy(QUADRATIC *to, QUADRATIC *from) {
	int code;
	
	code = LIBLESS_ERROR;
	
	TRY(BN_copy(to->x, from->x), goto end);
	TRY(BN_copy(to->y, from->y), goto end);
	
	code = LIBLESS_OK;
end:
	return code;
}

int QD_equal(QUADRATIC *a, QUADRATIC *b) {
	return (BN_cmp(a->x, b->x) == 0 && BN_cmp(a->y, b->y) == 0);
}

void QD_free(QUADRATIC *a) {
	if (a != NULL) {
		if (a->x != NULL) {
			BN_free(a->x);
		}
		if (a->y != NULL) {
			BN_free(a->y);
		}
		free(a);
	}
}
