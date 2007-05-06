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
 * @file libless.c
 * 
 * Implementation of the Certificateless Public Key Cryptography aggregate 
 * signature module.
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

#include <liberror.h>

#include "libless.h"
#include "libless_error.h"
#include "libless_quadratic.h"
#include "libless_pairing.h"
#include "libless_types.h"
#include "libless_timing.h"
#include "libless_util.h"
#include "libless_aggregate.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int libless_aggregate_setup(libless_t *env, libless_params_t *parameters,
		libless_master_t *master_key) {
	BN_CTX *ctx = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *bt = NULL;
	BIGNUM *p = NULL;
	BIGNUM *n = NULL;
	BIGNUM *nt = NULL;
	BIGNUM *r = NULL;
	BIGNUM *h = NULL;
	BIGNUM *ht = NULL;
	BIGNUM *x = NULL;
	EC_GROUP *group = NULL;
	EC_GROUP *twisted = NULL;
	EC_POINT *g = NULL;
	EC_POINT *gt = NULL;
	EC_POINT *public = NULL;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(a = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(b = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(p = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(n = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(bt = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(nt = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(ht = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(x = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(*master_key = BN_new(), ERR(REASON_MEMORY));

	code = LIBLESS_ERROR;

	TRY(BN_hex2bn(&a, CURVE_A), ERR(REASON_CURVE_PARAMETERS));
	TRY(BN_hex2bn(&b, CURVE_B), ERR(REASON_CURVE_PARAMETERS));
	TRY(BN_hex2bn(&p, CURVE_P), ERR(REASON_CURVE_PARAMETERS));
	TRY(BN_hex2bn(&h, CURVE_H), ERR(REASON_CURVE_PARAMETERS));
	TRY(BN_hex2bn(&r, CURVE_R), ERR(REASON_CURVE_PARAMETERS));
	TRY(BN_hex2bn(&bt, TWISTED_B), ERR(REASON_CURVE_PARAMETERS));
	TRY(BN_hex2bn(&ht, TWISTED_H), ERR(REASON_CURVE_PARAMETERS));

	/* Create the curve from the imported parameters. */
	TRY(group = EC_GROUP_new_curve_GFp(p, a, b, ctx),
			ERR(REASON_CURVE_PARAMETERS));
	TRY(twisted = EC_GROUP_new_curve_GFp(p, a, bt, ctx),
			ERR(REASON_CURVE_PARAMETERS));

	TRY(g = EC_POINT_new(group), ERR(REASON_MEMORY));
	TRY(gt = EC_POINT_new(twisted), ERR(REASON_MEMORY));
	TRY(public = EC_POINT_new(group), ERR(REASON_MEMORY));

	/* Generate a random point in the curve. */
	do {
		do {
			/* First, generate a random x value. */
			TRY(BN_rand(x, P_SIZE_BITS, -1, 0), ERR(REASON_OPENSSL));
		} while (!EC_POINT_set_compressed_coordinates_GFp(group, g, x, 0,
						ctx));

		/* Multiply the random point by the cofactor. */
		TRY(EC_POINT_mul(group, g, NULL, g, h, ctx), ERR(REASON_OPENSSL));

	} while (EC_POINT_is_at_infinity(group, g));

	/* Set the subgroup generator. */
	TRY(EC_GROUP_set_generator(group, g, r, h), ERR(REASON_OPENSSL));

	/* Precompute multiples of the generator. */
	TRY(EC_GROUP_precompute_mult(group, ctx), ERR(REASON_OPENSSL));

	/* Verify the curve group. */
	TRY(EC_GROUP_check(group, ctx), ERR(REASON_CURVE_PARAMETERS));

	/* Generate a random point in the twisted curve. */
	do {
		do {
			/* First, generate a random x value. */
			TRY(BN_rand(x, P_SIZE_BITS, -1, 0), ERR(REASON_OPENSSL));
		} while (!EC_POINT_set_compressed_coordinates_GFp(twisted, gt, x, 0,
						ctx) || EC_POINT_is_at_infinity(twisted, gt));

		/* Multiply the random point by the cofactor. */
		TRY(EC_POINT_mul(group, gt, NULL, gt, ht, ctx), ERR(REASON_OPENSSL));

	} while (EC_POINT_is_at_infinity(twisted, gt));

	/* Set a dummy generator. */
	TRY(EC_GROUP_set_generator(twisted, gt, r, NULL), ERR(REASON_OPENSSL));

	/* Check the group structure. */
	TRY(EC_GROUP_check(twisted, ctx), ERR(REASON_CURVE_PARAMETERS));

	do {
		TRY(BN_rand_range(*master_key, r), ERR(REASON_OPENSSL));

		TRY(EC_POINT_mul(group, public, *master_key, NULL, NULL, ctx),
				ERR(REASON_OPENSSL));

	} while (BN_is_zero(*master_key));

	TRY(parameters->group1 = EC_GROUP_dup(group), ERR(REASON_OPENSSL));
	TRY(parameters->group2 = EC_GROUP_dup(twisted), ERR(REASON_OPENSSL));
	TRY(parameters->public = EC_POINT_dup(public, group),
			ERR(REASON_OPENSSL));
	TRY(parameters->generator1 = EC_POINT_dup(g, group), ERR(REASON_OPENSSL));
	TRY(parameters->prime = BN_dup(p), ERR(REASON_OPENSSL));
	TRY(parameters->factor = BN_dup(r), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	EC_POINT_free(g);
	EC_POINT_free(gt);
	EC_POINT_free(public);
	EC_GROUP_free(group);
	EC_GROUP_free(twisted);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return code;
}

int libless_aggregate_extract(libless_t *env, libless_partial_t *key,
		unsigned char *id, int id_len, libless_master_t master,
		libless_params_t parameters) {
	BN_CTX *ctx = NULL;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(*key = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));

	TRY(libless_hash_to_point(env, *key, id, id_len, parameters.group2, ctx),
			ERR(REASON_HASH));

	TRY(EC_POINT_mul(parameters.group2, *key, NULL, *key, master, ctx),
			ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return code;
}

int libless_aggregate_set_secret(libless_t *env, libless_secret_t *secret,
		libless_params_t parameters) {
	int code;

	code = LIBLESS_ERROR;

	TRY(*secret = BN_new(), ERR(REASON_MEMORY));

	TRY(BN_rand_range(*secret, parameters.factor), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	return code;
}

int libless_aggregate_set_public(libless_t *env,
		libless_public_t *public_key, libless_secret_t secret,
		libless_params_t parameters) {
	BN_CTX *ctx;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));
	TRY(public_key->point =
			EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));

	TRY(EC_POINT_mul(parameters.group1, public_key->point, NULL,
					parameters.public, secret, ctx), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	BN_CTX_free(ctx);
	return code;
}

int libless_aggregate_set_private(libless_t *env,
		libless_private_t *private_key, libless_secret_t secret,
		libless_partial_t partial, libless_params_t parameters) {
	int code;

	code = LIBLESS_ERROR;
	if (secret == NULL || partial == NULL) {
		goto end;
	}

	TRY(private_key->secret = BN_dup(secret), ERR(REASON_OPENSSL));
	TRY(private_key->partial = EC_POINT_dup(partial, parameters.group2),
			ERR(REASON_MEMORY));
	EC_POINT_copy(private_key->partial, partial);

	code = LIBLESS_OK;
end:
	return code;
}

int libless_aggregate_batch_sign(libless_t *env,
		libless_aggregate_t *aggregate, unsigned char *id, int id_len,
		libless_public_t public_key, libless_private_t private_key,
		libless_params_t parameters, unsigned char *in, int in_len) {
	EC_POINT *image = NULL;
	EC_POINT *image2 = NULL;
	EC_POINT *hash = NULL;
	EC_POINT *id_point = NULL;
	EC_POINT *id_point2 = NULL;
	BIGNUM *r = NULL;
	BIGNUM *h = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *h_bin = NULL;
	unsigned char *hash_bin = NULL;
	unsigned char **image_bin;
	int h_len;
	int i;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	TRY(image = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));
	TRY(image2 = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(hash = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(id_point = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(id_point2 = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));

	h_len = in_len + 2 * POINT_SIZE_BYTES;
	TRY(h_bin = (unsigned char *)calloc(h_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));

	TRY(image_bin = (unsigned char **)calloc(aggregate->signatures,
					sizeof(unsigned char *)), ERR(REASON_MEMORY));

	for (i = 0; i < aggregate->signatures; i++)
		TRY(image_bin[i] = (unsigned char *)
				calloc(POINT_SIZE_BYTES, sizeof(unsigned char)),
				ERR(REASON_MEMORY));

	TRY(hash_bin = (unsigned char *)
			calloc(POINT_SIZE_BYTES, sizeof(unsigned char)),
			ERR(REASON_MEMORY));

	/* Map the id to a point in the twisted curve. */
	TRY(libless_hash_to_point(env, id_point, id, id_len, parameters.group2,
					ctx), ERR(REASON_HASH));
	TRY(EC_POINT_copy(id_point2, id_point), ERR(REASON_OPENSSL));

	for (i = 0; i < aggregate->signatures; i++) {
		/* Create a random session key r. */
		TRY(BN_rand_range(r, parameters.factor), ERR(REASON_OPENSSL));

		/* Multiply P by r. */
		TRY(EC_POINT_mul(parameters.group1, image, r, NULL, NULL, ctx),
				ERR(REASON_OPENSSL));

		/* Hash the message, the image of the session key, and the public key to
		 * an integer. */
		memcpy(h_bin, in, in_len);
		TRY(EC_POINT_point2oct(parameters.group1, image,
						POINT_CONVERSION_COMPRESSED, h_bin, h_len, ctx),
				ERR(REASON_OPENSSL));
		TRY(EC_POINT_point2oct(parameters.group1, public_key.point,
						POINT_CONVERSION_COMPRESSED, h_bin + POINT_SIZE_BYTES,
						h_len - POINT_SIZE_BYTES, ctx), ERR(REASON_OPENSSL));
		TRY(libless_hash_to_integer(env, h, h_bin, h_len, parameters.factor),
				ERR(REASON_HASH));

		/* Multiply id_point by r. */
		TRY(EC_POINT_mul(parameters.group2, id_point2, NULL, id_point, r,
						ctx), ERR(REASON_OPENSSL));

		TRY(BN_mod_mul(h, h, private_key.secret, parameters.factor, ctx),
				ERR(REASON_OPENSSL));

		TRY(EC_POINT_mul(parameters.group2, image2, NULL, private_key.partial,
						h, ctx), ERR(REASON_OPENSSL));

		TRY(EC_POINT_add(parameters.group2, image2, id_point2, image2, ctx),
				ERR(REASON_OPENSSL));

		if (i == 0) {
			TRY(EC_POINT_copy(hash, image2), ERR(REASON_OPENSSL));
		}
		else {
			TRY(EC_POINT_add(parameters.group2, hash, hash, image2, ctx),
					ERR(REASON_OPENSSL));
		}

		/* Export the signature values. */
		TRY(EC_POINT_point2oct(parameters.group1, image,
						POINT_CONVERSION_COMPRESSED, image_bin[i],
						POINT_SIZE_BYTES, ctx), ERR(REASON_OPENSSL));

		aggregate->signature[i].image = image_bin[i];
		aggregate->signature[i].image_len = POINT_SIZE_BYTES;
	}

	TRY(EC_POINT_point2oct(parameters.group1, hash,
					POINT_CONVERSION_COMPRESSED, hash_bin, POINT_SIZE_BYTES,
					ctx), ERR(REASON_OPENSSL));

	aggregate->signature[0].hash = hash_bin;
	aggregate->signature[0].hash_len = POINT_SIZE_BYTES;

	code = LIBLESS_OK;

end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_POINT_free(image);
	free(h_bin);
	return code;
}

int libless_aggregate_batch_verify(libless_t *env, int *verified,
		libless_aggregate_t aggregate, unsigned char *id, int id_len,
		libless_public_t public_key, libless_params_t parameters,
		unsigned char *in, int in_len, ...) {
	EC_POINT *image = NULL;
	EC_POINT *image2 = NULL;
	EC_POINT *hash = NULL;
	EC_POINT *hash2 = NULL;
	EC_POINT *id_point = NULL;
	BIGNUM *h = NULL;
	BIGNUM *e1 = NULL;
	BIGNUM *e2 = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *h_bin = NULL;
	int h_len;
	int i;
	int code;

	code = LIBLESS_ERROR;
	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e1 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e2 = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	h_len = in_len + 2 * POINT_SIZE_BYTES;

	TRY(h_bin = (unsigned char *)calloc(h_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(image = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));
	TRY(image2 = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(hash = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(hash2 = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(id_point = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));

	TRY(EC_POINT_oct2point(parameters.group2, image2,
					aggregate.signature[0].hash,
					aggregate.signature[0].hash_len, ctx),
			ERR(REASON_OPENSSL));

	for (i = 0; i < aggregate.signatures; i++) {

		/* Recover the points received with the signature. */
		TRY(EC_POINT_oct2point(parameters.group1, image,
						aggregate.signature[i].image,
						aggregate.signature[i].image_len, ctx),
				ERR(REASON_OPENSSL));

		/* Hash the message, the image of the session key, and the public key to
		 * an integer. */
		memcpy(h_bin, in, in_len);
		TRY(EC_POINT_point2oct(parameters.group1, image,
						POINT_CONVERSION_COMPRESSED, h_bin, h_len, ctx),
				ERR(REASON_OPENSSL));
		TRY(EC_POINT_point2oct(parameters.group1, public_key.point,
						POINT_CONVERSION_COMPRESSED, h_bin + POINT_SIZE_BYTES,
						h_len - POINT_SIZE_BYTES, ctx), ERR(REASON_OPENSSL));
		TRY(libless_hash_to_integer(env, h, h_bin, h_len, parameters.factor),
				ERR(REASON_HASH));

		/* Map the id to a point in the twisted curve. */
		TRY(libless_hash_to_point(env, id_point, id, id_len,
						parameters.group2, ctx), ERR(REASON_HASH));

		TRY(EC_POINT_mul(parameters.group1, hash, NULL, public_key.point, h,
						ctx), ERR(REASON_OPENSSL));

		TRY(EC_POINT_add(parameters.group1, image, image, hash, ctx),
				ERR(REASON_OPENSSL));

		if (i == 0) {
			TRY(EC_POINT_copy(hash2, image), ERR(REASON_OPENSSL));
		}
		else {
			TRY(EC_POINT_add(parameters.group1, hash2, hash2, image, ctx),
					ERR(REASON_OPENSSL));
		}

	}

	TRY(libless_pairing(env, e1, parameters.generator1, image2, NULL,
					parameters, ctx), ERR(REASON_PAIRING));

	TRY(libless_pairing(env, e2, hash2, id_point, NULL, parameters, ctx),
			ERR(REASON_OPENSSL));

	/* Compare the image received and the image computed. */
	if (BN_cmp(e1, e2) == 0) {
		*verified = 1;
	}
	else {
		*verified = 0;
	}

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_POINT_free(id_point);
	EC_POINT_free(image);
	free(h_bin);
	return code;
}

int libless_aggregate_verify(libless_t *env, int *verified,
		libless_aggregate_t aggregate, unsigned char *id, int id_len,
		libless_public_t public_key, libless_params_t parameters,
		unsigned char *in, int in_len, ...) {
	EC_POINT *image = NULL;
	EC_POINT *image2 = NULL;
	EC_POINT *hash = NULL;
	EC_POINT *hash2 = NULL;
	EC_POINT *id_point = NULL;
	BIGNUM *h = NULL;
	BIGNUM *e = NULL;
	BIGNUM *e1 = NULL;
	BIGNUM *e2 = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *h_bin = NULL;
	int h_len;
	int i;
	int code;

	code = LIBLESS_ERROR;
	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e1 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e2 = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	h_len = in_len + 2 * POINT_SIZE_BYTES;

	TRY(h_bin = (unsigned char *)calloc(h_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(image = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));
	TRY(image2 = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(hash = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(hash2 = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(id_point = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));

	TRY(EC_POINT_oct2point(parameters.group2, image2,
					aggregate.signature[0].hash,
					aggregate.signature[0].hash_len, ctx),
			ERR(REASON_OPENSSL));

	for (i = 0; i < aggregate.signatures; i++) {

		/* Recover the points received with the signature. */
		TRY(EC_POINT_oct2point(parameters.group1, image,
						aggregate.signature[i].image,
						aggregate.signature[i].image_len, ctx),
				ERR(REASON_OPENSSL));

		/* Hash the message, the image of the session key, and the public key to
		 * an integer. */
		memcpy(h_bin, in, in_len);
		TRY(EC_POINT_point2oct(parameters.group1, image,
						POINT_CONVERSION_COMPRESSED, h_bin, h_len, ctx),
				ERR(REASON_OPENSSL));
		TRY(EC_POINT_point2oct(parameters.group1, public_key.point,
						POINT_CONVERSION_COMPRESSED, h_bin + POINT_SIZE_BYTES,
						h_len - POINT_SIZE_BYTES, ctx), ERR(REASON_OPENSSL));
		TRY(libless_hash_to_integer(env, h, h_bin, h_len, parameters.factor),
				ERR(REASON_HASH));

		/* Map the id to a point in the twisted curve. */
		TRY(libless_hash_to_point(env, id_point, id, id_len,
						parameters.group2, ctx), ERR(REASON_HASH));

		TRY(EC_POINT_mul(parameters.group1, hash, NULL, public_key.point, h,
						ctx), ERR(REASON_OPENSSL));

		TRY(EC_POINT_add(parameters.group1, image, image, hash, ctx),
				ERR(REASON_OPENSSL));

		TRY(libless_pairing(env, e, image, id_point, NULL, parameters, ctx),
				ERR(REASON_OPENSSL));

		if (i == 0) {
			TRY(BN_copy(e2, e), ERR(REASON_OPENSSL));
		}
		else {
			TRY(libless_pairing_multiply(env, e2, NULL, e2, e, parameters,
							ctx), ERR(REASON_PAIRING));
		}
	}

	TRY(libless_pairing(env, e1, parameters.generator1, image2, NULL,
					parameters, ctx), ERR(REASON_PAIRING));

	/* Compare the image received and the image computed. */
	if (BN_cmp(e1, e2) == 0) {
		*verified = 1;
	}
	else {
		*verified = 0;
	}

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_POINT_free(id_point);
	EC_POINT_free(image);
	free(h_bin);
	return code;
}
