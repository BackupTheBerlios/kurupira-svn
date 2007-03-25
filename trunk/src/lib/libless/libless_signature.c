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
 * Implementation of the Certificateless Public Key Cryptography signature
 * module.
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
#include "libless_err.h"
#include "libless_quadratic.h"
#include "libless_pairing.h"
#include "libless_types.h"
#include "libless_timing.h"
#include "libless_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int libless_signature_setup(libless_t *env, libless_params_t *parameters,
		libless_master_t *master_key) {
	BN_CTX *ctx = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *bt = NULL;
	BIGNUM *p = NULL;
	BIGNUM *n = NULL;
	BIGNUM *nt = NULL;
	BIGNUM *r = NULL;
	BIGNUM *e = NULL;
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
	TRY(n = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(p = BN_new(), ERR(REASON_MEMORY));
	TRY(r = BN_new(), ERR(REASON_MEMORY));
	TRY(e = BN_new(), ERR(REASON_MEMORY));
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
		} while (!EC_POINT_set_compressed_coordinates_GFp(group, g, x, 0, ctx));

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
		TRY(EC_POINT_mul(twisted, gt, NULL, gt, ht, ctx), ERR(REASON_OPENSSL));

	} while (EC_POINT_is_at_infinity(twisted, gt));

	/* Set the twisted curve generator. */
	TRY(EC_GROUP_set_generator(twisted, gt, r, NULL), ERR(REASON_OPENSSL));

	/* Precompute multiples of the generator. */
	TRY(EC_GROUP_precompute_mult(twisted, ctx), ERR(REASON_OPENSSL));

	/* Check the group structure. */
	TRY(EC_GROUP_check(twisted, ctx), ERR(REASON_CURVE_PARAMETERS));

	/* Generate the master key. */
	do {
		TRY(BN_rand_range(*master_key, r), ERR(REASON_OPENSSL));

		TRY(EC_POINT_mul(twisted, public, *master_key, NULL, NULL, ctx),
				ERR(REASON_OPENSSL));
	} while (BN_is_zero(*master_key));

	parameters->group1 = group;
	parameters->group2 = twisted;
	parameters->public = public;
	parameters->generator1 = g;
	parameters->generator2 = gt;
	parameters->prime = p;
	parameters->factor = r;

	/* Compute the pairing. */
	TRY(libless_pairing(env, e, g, gt, NULL, *parameters, ctx),
			ERR(REASON_PAIRING));

	parameters->pairing = e;

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return code;
}

int libless_signature_extract(libless_t *env, libless_partial_t *key,
		unsigned char *id, int id_len, libless_master_t master,
		libless_params_t parameters) {
	BN_CTX *ctx = NULL;
	BIGNUM *h = NULL;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	TRY(*key = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));

	TRY(libless_hash_to_integer(env, h, id, id_len, parameters.factor),
			ERR(REASON_HASH));

	TRY(BN_mod_add_quick(h, h, master, parameters.factor), ERR(REASON_OPENSSL));

	TRY(BN_mod_inverse(h, h, parameters.factor, ctx), ERR(REASON_OPENSSL));

	TRY(EC_POINT_mul(parameters.group1, *key, h, NULL, NULL, ctx),
			ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return code;
}
int libless_signature_set_secret(libless_t *env, libless_secret_t *secret,
		libless_params_t parameters) {
	int code;

	code = LIBLESS_ERROR;

	TRY(*secret = BN_new(), ERR(REASON_MEMORY));

	TRY(BN_rand_range(*secret, parameters.factor), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:return code;
}
int libless_signature_set_public(libless_t *env, libless_public_t *public_key,
		libless_secret_t secret, libless_params_t parameters) {
	BN_CTX *ctx;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	TRY(public_key->pairing = BN_new(), ERR(REASON_MEMORY));

	/* The public key is a power of a pairing. So, we have to compute this power
	 * using the special function. */
	TRY(libless_pairing_power(env, public_key->pairing, parameters.pairing,
					secret, parameters, ctx), ERR(REASON_PAIRING));

	code = LIBLESS_OK;
end:BN_CTX_free(ctx);
	return code;
}
int libless_signature_set_private(libless_t *env,
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
	TRY(EC_POINT_copy(private_key->partial, partial), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	return code;
}

int libless_sign(libless_t *env, libless_signature_t * signature,
		unsigned char *in, int in_len, unsigned char *id, int id_len,
		libless_public_t public_key, libless_private_t private_key,
		libless_params_t parameters) {
	EC_POINT *image = NULL;
	BIGNUM *k = NULL;
	BIGNUM *r = NULL;
	BIGNUM *h = NULL;
	BIGNUM *e = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *h_bin = NULL;
	unsigned char *hash_bin = NULL;
	unsigned char *image_bin = NULL;
	int h_len;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(k = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	TRY(image = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));

	h_len = in_len + id_len + 2 * P_SIZE_BYTES;
	TRY(h_bin = (unsigned char *)calloc(h_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(image_bin = (unsigned char *)
			calloc(POINT_SIZE_BYTES, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(hash_bin = (unsigned char *)
			calloc(R_SIZE_BYTES, sizeof(unsigned char)), ERR(REASON_MEMORY));

	/* Create a random session key. */
	TRY(BN_rand_range(k, parameters.factor), ERR(REASON_OPENSSL));

	/* Compute r = g^k with special power function. */
	TRY(libless_pairing_power(env, r, parameters.pairing, k, parameters,
					ctx), ERR(REASON_OPENSSL));

	/* Hash the message, the identity, the public key and the session key to
	 * a integer. */
	memcpy(h_bin, in, in_len);
	memcpy(h_bin + in_len, id, id_len);
	TRY(BN_bn2bin(public_key.pairing, h_bin + in_len + id_len),
			ERR(REASON_OPENSSL));
	TRY(BN_bn2bin(r, h_bin + in_len + id_len + P_SIZE_BYTES),
			ERR(REASON_OPENSSL));
	TRY(libless_hash_to_integer(env, h, h_bin, h_len, parameters.factor),
			ERR(REASON_HASH));

	/* Export the signature values. */
	TRY(BN_bn2bin(h, hash_bin), ERR(REASON_OPENSSL));
	signature->hash_len = BN_num_bytes(h);

	/* Compute S = (k + hd_a)D_A. */
	TRY(BN_mod_mul(h, h, private_key.secret, parameters.factor, ctx),
			ERR(REASON_OPENSSL));
	TRY(BN_mod_add_quick(h, h, k, parameters.factor), ERR(REASON_OPENSSL));

	/* Multiply the partial private key by h. */
	TRY(EC_POINT_mul(parameters.group1, image, NULL, private_key.partial, h,
					ctx), ERR(REASON_OPENSSL));

	TRY(EC_POINT_point2oct(parameters.group1, image,
					POINT_CONVERSION_COMPRESSED, image_bin, POINT_SIZE_BYTES,
					ctx), ERR(REASON_OPENSSL));

	signature->hash = hash_bin;
	signature->image = image_bin;
	signature->image_len = POINT_SIZE_BYTES;

	code = LIBLESS_OK;
end:BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_POINT_free(image);
	free(h_bin);
	return code;
}
int libless_verify(libless_t *env, int *verified,
		libless_signature_t signature, unsigned char *in, int in_len,
		unsigned char *id, int id_len, libless_public_t public_key,
		libless_params_t parameters) {
	EC_POINT *image = NULL;
	EC_POINT *id_point = NULL;
	BIGNUM *h1 = NULL;
	BIGNUM *h2 = NULL;
	BIGNUM *hash = NULL;
	BIGNUM *e = NULL;
	BIGNUM *r = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *r2 = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *h_bin = NULL;
	int h_len;
	int code;

	code = LIBLESS_ERROR;
	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(h1 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(h2 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(hash = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(r1 = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(r2 = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	h_len = in_len + id_len + 2 * P_SIZE_BYTES;

	TRY(h_bin = (unsigned char *)calloc(h_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(image = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));
	TRY(id_point = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));

	/* Recover the point received with the signature. */
	TRY(EC_POINT_oct2point(parameters.group1, image, signature.image,
					signature.image_len, ctx), ERR(REASON_OPENSSL));

	/* Recover the hash received with the signature. */
	TRY(BN_bin2bn(signature.hash, signature.hash_len, hash),
			ERR(REASON_OPENSSL));

	/* Compute H(ID_A)Q + Q_0. */
	TRY(libless_hash_to_integer(env, h1, id, id_len, parameters.factor),
			ERR(REASON_HASH));

	TRY(EC_POINT_mul(parameters.group2, id_point, h1, NULL, NULL, ctx),
			ERR(REASON_OPENSSL));

	TRY(EC_POINT_add(parameters.group2, id_point, id_point,
					parameters.public, ctx), ERR(REASON_OPENSSL));

	TRY(libless_pairing(env, e, image, id_point, NULL, parameters, ctx),
			ERR(REASON_PAIRING));

	TRY(libless_pairing_power(env, r, public_key.pairing, hash, parameters,
					ctx), ERR(REASON_PAIRING));

	TRY(libless_pairing_multiply(env, r1, r2, e, r, parameters, ctx),
			ERR(REASON_PAIRING));

	/* Hash the message, the identity, the public key and the session key to
	 * an integer. */
	memcpy(h_bin, in, in_len);
	memcpy(h_bin + in_len, id, id_len);
	TRY(BN_bn2bin(public_key.pairing, h_bin + in_len + id_len),
			ERR(REASON_OPENSSL));
	TRY(BN_bn2bin(r1, h_bin + in_len + id_len + P_SIZE_BYTES),
			ERR(REASON_OPENSSL));
	TRY(libless_hash_to_integer(env, h1, h_bin, h_len, parameters.factor),
			ERR(REASON_HASH));

	memset(h_bin + in_len + id_len + P_SIZE_BYTES, 0, P_SIZE_BYTES);
	TRY(BN_bn2bin(r2, h_bin + in_len + id_len + P_SIZE_BYTES),
			ERR(REASON_OPENSSL));
	TRY(libless_hash_to_integer(env, h2, h_bin, h_len, parameters.factor),
			ERR(REASON_HASH));

	/* Compare the image received and the image computed. */
	if (BN_cmp(h1, hash) == 0 || BN_cmp(h2, hash) == 0) {
		*verified = 1;
	} else {
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
