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
 * @file libless_encryption.c
 * 
 * Implementation of the Certificateless Public Key Cryptography encryption 
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

#include "libless.h"
#include "libless_err.h"
#include "libless_pairing.h"
#include "libless_types.h"
#include "libless_quadratic.h"
#include "libless_timing.h"
#include "libless_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int libless_encryption_setup(libless_t *env, libless_params_t *parameters,
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
	TRY(p = BN_new(), ERR(REASON_MEMORY));
	TRY(n = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(r = BN_new(), ERR(REASON_MEMORY));
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

	parameters->group1 = group;
	parameters->group2 = twisted;
	parameters->public = public;
	parameters->prime = p;
	parameters->generator1 = g;
	parameters->factor = r;

	code = LIBLESS_OK;
end:
	EC_POINT_free(gt);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return code;
}

int libless_encryption_extract(libless_t *env, libless_partial_t *key,
		unsigned char *id, int id_len, libless_master_t master,
		libless_params_t parameters) {
	BN_CTX *ctx = NULL;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(*key = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	INIT_TIMING();
	TIMING_BEFORE();
	TRY(libless_hash_to_point(env, *key, id, id_len, parameters.group2, ctx),
			ERR(REASON_HASH));
	TIMING_AFTER();
	COMPUTE_TIMING(hash);

	TRY(EC_POINT_mul(parameters.group2, *key, NULL, *key, master, ctx),
			ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return code;
}

int libless_encryption_set_secret(libless_t *env, libless_secret_t *secret,
		libless_params_t parameters) {
	int code;

	code = LIBLESS_ERROR;

	TRY(*secret = BN_new(), ERR(REASON_MEMORY));

	TRY(BN_rand_range(*secret, parameters.factor), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	return code;
}

int libless_encryption_set_public(libless_t *env,
		libless_public_t *public_key, libless_secret_t secret,
		libless_params_t parameters) {
	BN_CTX *ctx;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));
	TRY(public_key->point =
			EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));

	TRY(EC_POINT_mul(parameters.group1, public_key->point, secret, NULL, NULL,
					ctx), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	BN_CTX_free(ctx);
	return code;
}

int libless_encryption_set_private(libless_t *env,
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

int libless_encrypt(libless_t *env, libless_ciphertext_t *encrypted,
		unsigned char *in, int in_len, unsigned char *id, int id_len,
		libless_public_t public_key, libless_params_t parameters) {
	EC_POINT *image = NULL;
	EC_POINT *image_public = NULL;
	EC_POINT *id_point = NULL;
	BIGNUM *r = NULL;
	BIGNUM *e = NULL;
	BN_CTX *ctx = NULL;
	unsigned char key[CIPHER_KEY_LENGTH];
	unsigned char digest[HASH_LENGTH];
	unsigned char *h1_bin = NULL;
	unsigned char *h2_bin = NULL;
	unsigned char *envelope = NULL;
	unsigned char *data = NULL;
	unsigned char *image_bin = NULL;
	int h1_len;
	int h2_len;
	int env_len;
	int data_len;
	int code;


	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e = BN_CTX_get(ctx), ERR(REASON_MEMORY));

	TRY(id_point = EC_POINT_new(parameters.group2), ERR(REASON_MEMORY));
	TRY(image = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));
	TRY(image_public = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));

	h1_len = in_len + CIPHER_KEY_LENGTH;
	h2_len = 2 * POINT_SIZE_BYTES + P_SIZE_BYTES;
	env_len = CIPHER_KEY_LENGTH + CIPHER_LENGTH;
	data_len = in_len + CIPHER_LENGTH;

	TRY(h1_bin = (unsigned char *)calloc(h1_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(h2_bin = (unsigned char *)calloc(h2_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(image_bin = (unsigned char *)
			calloc(POINT_SIZE_BYTES, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(envelope = (unsigned char *)calloc(env_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(data = (unsigned char *)calloc(data_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));

	/* Map the id to a point in the twisted curve. */
	TRY(libless_hash_to_point(env, id_point, id, id_len, parameters.group2,
					ctx), ERR(REASON_HASH));

	/* Create a random key. */
	TRY(RAND_bytes(key, CIPHER_KEY_LENGTH), ERR(REASON_OPENSSL));

	/* Hash the key and the message to a integer modulo r. */
	memcpy(h1_bin, key, CIPHER_KEY_LENGTH);
	memcpy(h1_bin + CIPHER_KEY_LENGTH, in, in_len);
	TRY(libless_hash_to_integer(env, r, h1_bin, h1_len, parameters.factor),
			ERR(REASON_HASH));


	/* Multiply the generator by r. */
	TRY(EC_POINT_mul(parameters.group1, image, r, NULL, NULL, ctx),
			ERR(REASON_OPENSSL));


	/* Multiply the public key by r. */
	TRY(EC_POINT_mul(parameters.group1, image_public, NULL, public_key.point, r,
					ctx), ERR(REASON_OPENSSL));

	/* Compute the pairing. */
	TRY(libless_pairing(env, e, parameters.public, id_point, r, parameters,
					ctx), ERR(REASON_PAIRING));

	/* Hash the image, the public key and the pairing result. */
	TRY(EC_POINT_point2oct(parameters.group1, image,
					POINT_CONVERSION_COMPRESSED, h2_bin, h2_len, ctx),
			ERR(REASON_OPENSSL));
	TRY(EC_POINT_point2oct(parameters.group1, image_public,
					POINT_CONVERSION_COMPRESSED, h2_bin + POINT_SIZE_BYTES,
					h2_len - POINT_SIZE_BYTES, ctx), ERR(REASON_OPENSSL));

	TRY(BN_bn2bin(e, h2_bin + 2 * POINT_SIZE_BYTES), ERR(REASON_OPENSSL));

	TRY(libless_hash(env, digest, h2_bin, h2_len), ERR(REASON_HASH));

	/* Encrypt the key with the hash of the above. */
	TRY(libless_cipher(env, envelope, &env_len, key, CIPHER_KEY_LENGTH, digest,
					CIPHER_ENCRYPT), ERR(REASON_CIPHER));

	/* Hash the key. */
	TRY(libless_hash(env, digest, key, CIPHER_KEY_LENGTH), ERR(REASON_HASH));

	/* Encrypt the data with the hash of the key. */
	TRY(libless_cipher(env, data, &data_len, in, in_len, digest,
					CIPHER_ENCRYPT), ERR(REASON_CIPHER));

	TRY(EC_POINT_point2oct(parameters.group1, image,
					POINT_CONVERSION_COMPRESSED, image_bin, POINT_SIZE_BYTES,
					ctx), ERR(REASON_OPENSSL));

	encrypted->image = image_bin;
	encrypted->image_len = POINT_SIZE_BYTES;
	encrypted->envelope = envelope;
	encrypted->env_len = env_len;
	encrypted->data = data;
	encrypted->data_len = data_len;

	code = LIBLESS_OK;
end:
	EC_POINT_free(id_point);
	EC_POINT_free(image_public);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	free(h1_bin);
	free(h2_bin);
	return code;
}

int libless_decrypt(libless_t *env, unsigned char *out, int *out_len,
		libless_ciphertext_t encrypted, libless_private_t private_key,
		libless_params_t parameters) {
	EC_POINT *image = NULL;
	EC_POINT *image2 = NULL;
	BIGNUM *n = NULL;
	BIGNUM *r = NULL;
	BIGNUM *e = NULL;
	BN_CTX *ctx = NULL;
	unsigned char key[CIPHER_KEY_LENGTH];
	unsigned char digest[HASH_LENGTH];
	unsigned char *h1_bin = NULL;
	unsigned char *h2_bin = NULL;
	unsigned char *data = NULL;
	int h1_len;
	int h2_len;
	int key_len;
	int data_len;
	int code;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(n = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(r = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(e = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(image = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));
	TRY(image2 = EC_POINT_new(parameters.group1), ERR(REASON_MEMORY));	

	h1_len = 2 * POINT_SIZE_BYTES + P_SIZE_BYTES;
	h2_len = CIPHER_KEY_LENGTH + encrypted.data_len;
	data_len = encrypted.data_len;

	TRY(h1_bin = (unsigned char *)calloc(h1_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(h2_bin = (unsigned char *)calloc(h2_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));
	TRY(data = (unsigned char *)calloc(data_len, sizeof(unsigned char)),
			ERR(REASON_MEMORY));

	/* Recover the point received with the ciphertext. */
	TRY(EC_POINT_oct2point(parameters.group1, image, encrypted.image,
					encrypted.image_len, ctx), ERR(REASON_OPENSSL));

	/* Hash the image, the image of the secret and the pairing result. */
	TRY(EC_POINT_point2oct(parameters.group1, image,
					POINT_CONVERSION_COMPRESSED, h1_bin, h1_len, ctx),
			ERR(REASON_OPENSSL));

	TRY(EC_POINT_mul(parameters.group1, image2, NULL, image,
					private_key.secret, ctx), ERR(REASON_OPENSSL));

	TRY(EC_POINT_point2oct(parameters.group1, image2,
					POINT_CONVERSION_COMPRESSED, h1_bin + POINT_SIZE_BYTES,
					h1_len - POINT_SIZE_BYTES, ctx), ERR(REASON_OPENSSL));

	TRY(libless_pairing(env, e, image, private_key.partial, NULL,
					parameters, ctx), ERR(REASON_PAIRING));

	TRY(BN_bn2bin(e, h1_bin + 2 * POINT_SIZE_BYTES), ERR(REASON_OPENSSL));

	TRY(libless_hash(env, digest, h1_bin, h1_len), ERR(REASON_HASH));

	/* Decrypt the key with the hash of the above. */
	TRY(libless_cipher(env, key, &key_len, encrypted.envelope,
					encrypted.env_len, digest, CIPHER_DECRYPT),
			ERR(REASON_CIPHER));

	/* Hash the key. */
	TRY(libless_hash(env, digest, key, CIPHER_KEY_LENGTH), ERR(REASON_HASH));

	/* Decrypt the data with the key. */
	TRY(libless_cipher(env, data, &data_len, encrypted.data,
					encrypted.data_len, digest, CIPHER_DECRYPT),
			ERR(REASON_CIPHER));

	/* Get the group order. */
	TRY(EC_GROUP_get_order(parameters.group1, n, ctx), ERR(REASON_OPENSSL));

	/* Hash the key and the message to a integer modulo n. */
	memcpy(h2_bin, key, CIPHER_KEY_LENGTH);
	memcpy(h2_bin + CIPHER_KEY_LENGTH, data, data_len);
	TRY(libless_hash_to_integer(env, r, h2_bin, CIPHER_KEY_LENGTH + data_len,
					parameters.factor), ERR(REASON_HASH));

	/* Multiply the generator by r. */
	TRY(EC_POINT_copy(image2, parameters.generator1), ERR(REASON_OPENSSL));
	TRY(EC_POINT_mul(parameters.group1, image2, r, NULL, NULL, ctx),
			ERR(REASON_OPENSSL));

	/* Compare the image received and the image computed. */
	if (EC_POINT_cmp(parameters.group1, image, image2, ctx) != 0) {
		*out_len = 0;
		ERR(REASON_DECRYPTION);
	} else {
		memcpy(out, data, data_len);
		*out_len = data_len;
	}

	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	free(h1_bin);
	free(h2_bin);
	free(data);
	return code;
}
