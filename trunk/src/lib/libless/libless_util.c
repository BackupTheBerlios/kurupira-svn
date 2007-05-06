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
 * @file libless_util.c
 * 
 * Hash functions and cipher utilities.
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
#include "libless_error.h"
#include "libless_quadratic.h"
#include "libless_pairing.h"
#include "libless_types.h"
#include "libless_timing.h"
#include "libless_util.h"

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/**
 * Cipher used.
 */
#define CIPHER_FUNCTION		EVP_aes_128_cbc()

/**
 * Hash function used.
 */
#define HASH_FUNCTION	EVP_sha1()

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int libless_cipher(libless_t *env, unsigned char *out, int *out_len,
		unsigned char *in, int in_len, unsigned char *key, int enc) {
	EVP_CIPHER_CTX ctx;
	int tmp_len;
	int code;

	code = LIBLESS_ERROR;

	EVP_CIPHER_CTX_init(&ctx);
	TRY(EVP_CipherInit_ex(&ctx, CIPHER_FUNCTION, NULL, key, NULL, enc),
			ERR(REASON_OPENSSL));
	TRY(EVP_CipherUpdate(&ctx, out, out_len, in, in_len), ERR(REASON_OPENSSL));
	TRY(EVP_CipherFinal_ex(&ctx, out + (*out_len), &tmp_len),
			ERR(REASON_OPENSSL));

	*out_len += tmp_len;

	code = LIBLESS_OK;
end:
	EVP_CIPHER_CTX_cleanup(&ctx);
	return code;
}

int libless_hash(libless_t *env, unsigned char *out,
		unsigned char *in, int in_len) {
	unsigned int out_len;
	EVP_MD_CTX ctx;

	int code;

	code = LIBLESS_ERROR;

	EVP_MD_CTX_init(&ctx);
	TRY(EVP_DigestInit_ex(&ctx, HASH_FUNCTION, NULL), ERR(REASON_OPENSSL));
	TRY(EVP_DigestUpdate(&ctx, in, in_len), ERR(REASON_OPENSSL));
	TRY(EVP_DigestFinal_ex(&ctx, out, &out_len), ERR(REASON_OPENSSL));

	code = LIBLESS_OK;
end:
	EVP_MD_CTX_cleanup(&ctx);
	return code;
}

int libless_hash_to_integer(libless_t *env, BIGNUM *number, unsigned char *in,
		int in_len, BIGNUM *p) {
	BIGNUM *h = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *h_bin = NULL;
	unsigned char digest[HASH_LENGTH];
	int limit;
	int h_len;
	int code;
	int i;

	code = LIBLESS_ERROR;

	TRY(ctx = BN_CTX_new(), ERR(REASON_MEMORY));

	BN_CTX_start(ctx);

	TRY(h = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(h_bin = (unsigned char *)
			calloc((HASH_LENGTH + in_len), sizeof(unsigned char)),
			ERR(REASON_MEMORY));

	/* Calculate the number of hash function interations. */
	// From IBCS #1, it could be: limit = (3.0 / 5.0) * BN_num_bits(p);
	limit = 1 + BN_num_bytes(p) / HASH_LENGTH;

	/* Fill number with zeroes. */
	TRY(BN_zero(number), ERR(REASON_OPENSSL));

	/* Set the initial digest to zero. */
	memset(digest, 0, HASH_LENGTH);

	/* Copy the byte vector to its position in the vector. This byte vector
	 * never changes and can be copied only once. */
	memcpy(h_bin + HASH_LENGTH, in, in_len);
	h_len = HASH_LENGTH + in_len;

	/* Iterate the hash function. */
	for (i = 0; i < limit; i++) {
		memcpy(h_bin, digest, HASH_LENGTH);
		TRY(libless_hash(env, digest, h_bin, h_len), ERR(REASON_HASH));

		/* Shift the current number, convert the hash into another number and
		 * add them. */
		TRY(BN_lshift(number, number, HASH_LENGTH << 3), ERR(REASON_OPENSSL));
		TRY(BN_bin2bn(digest, HASH_LENGTH, h), ERR(REASON_OPENSSL));
		TRY(BN_add(number, number, h), ERR(REASON_OPENSSL));
		TRY(BN_mod(number, number, p, ctx), ERR(REASON_OPENSSL));
	}
	code = LIBLESS_OK;
end:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	free(h_bin);
	return code;
}

int libless_hash_to_point(libless_t *env, EC_POINT *point,
		unsigned char *in, int in_len, EC_GROUP *group, BN_CTX *ctx) {
	unsigned char *in_bin = NULL;
	BIGNUM *x = NULL;
	BIGNUM *p = NULL;
	BIGNUM *n = NULL;
	int i, bit;
	int code;

	code = LIBLESS_ERROR;

	BN_CTX_start(ctx);

	TRY(x = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(p = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(n = BN_CTX_get(ctx), ERR(REASON_MEMORY));
	TRY(in_bin =
			(unsigned char *)malloc((in_len + 1) * sizeof(unsigned char)),
			ERR(REASON_MEMORY));

	/* Get the prime field order. */
	TRY(EC_GROUP_get_curve_GFp(group, p, NULL, NULL, ctx),
			ERR(REASON_CURVE_PARAMETERS));

	TRY(EC_GROUP_get_order(group, n, ctx), ERR(REASON_OPENSSL));
	i = 0;
	do {
		in_bin[0] = i++;
		/* Copy the identifier to our byte vector. */
		memcpy(in_bin + 1, in, in_len);
		/* Hash the id to a number in the prime field. */
		TRY(libless_hash_to_integer(env, x, in_bin, in_len + 1, p),
				ERR(REASON_HASH));

		bit = in_bin[0] & 0x01;
	} while (!EC_POINT_set_compressed_coordinates_GFp
			(group, point, x, bit, ctx));

	code = LIBLESS_OK;
end:
	free(in_bin);
	BN_CTX_end(ctx);
	return code;
}
