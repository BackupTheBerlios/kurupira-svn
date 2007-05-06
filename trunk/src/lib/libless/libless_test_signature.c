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
 * @file libless_test_signature.c
 * 
 * Test program for signature.
 * 
 * @version $Header$
 * @ingroup libless
 */

#include "string.h"
#include <time.h>

#include "libless.h"
#include "libless_error.h"
#include "libless_timing.h"
#include "libless_signature.h"
#include "openssl/engine.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int main(int argc, char *argv[]) {
	libless_t env;
	libless_params_t parameters;
	libless_master_t master_key;
	libless_partial_t partial_key;
	libless_secret_t secret;
	libless_public_t public_key;
	libless_private_t private_key;
	libless_signature_t signature;
	unsigned char id[] = { 'u', 's', 'e', 'r' };
	unsigned char data[] = { 'm', 'e', 's', 's', 'a', 'g', 'e', '\0' };
	int verified;
	int code;

	TIMING_INIT();

	code = LIBLESS_ERROR;

	libless_init(&env);
	libless_parameters_init(&parameters);
	libless_master_init(&master_key);
	libless_partial_init(&partial_key);
	libless_secret_init(&secret);
	libless_public_init(&public_key);
	libless_private_init(&private_key);
	libless_signature_init(&signature);

	TIMING_BEFORE();

	TRY(libless_signature_setup(&env, &parameters, &master_key), goto end);

	TIMING_AFTER();
	TIMING_COMPUTE(libless_signature_setup);

	printf("System parameters and master key generated.\n");

	TIMING_BEFORE();

	TRY(libless_signature_extract(&env, &partial_key, id, 4, master_key,
					parameters), goto end);

	TIMING_AFTER();
	TIMING_COMPUTE(libless_signature_extract);

	printf("Partial private key extracted.\n");

	TIMING_BEFORE();

	TRY(libless_signature_set_secret(&env, &secret, parameters), goto end);

	TIMING_AFTER();
	TIMING_COMPUTE(libless_signature_set_secret);

	printf("Secret value set.\n");

	TIMING_BEFORE();

	TRY(libless_signature_set_public(&env, &public_key, secret, parameters),
			goto end);

	TIMING_AFTER();
	TIMING_COMPUTE(libless_signature_set_public);

	printf("Public key set.\n");

	TIMING_BEFORE();

	TRY(libless_signature_set_private(&env, &private_key, secret, partial_key,
					parameters), goto end);

	TIMING_AFTER();
	TIMING_COMPUTE(libless_signature_set_private);

	printf("Private key set.\n");

	TIMING_BEFORE();

	TRY(libless_sign(&env, &signature, data, sizeof(data), id, 4, public_key,
					private_key, parameters), goto end);

	TIMING_AFTER();
	TIMING_COMPUTE(libless_sign);

	TIMING_BEFORE();

	verified = 0;
	TRY(libless_verify(&env, &verified, signature, data, sizeof(data), id, 4,
					public_key, parameters), goto end);

	TIMING_AFTER();
	TIMING_COMPUTE(libless_verify);

	ASSERT(verified, goto end);

	printf("Signature verified.\n");

	code = LIBLESS_OK;

  end:
	if (code == LIBLESS_ERROR) {
		printf("Test failed.\n");
	}
	else {
		printf("Test succeded.\n");
	}
	libless_signature_clean(&signature);
	libless_private_clean(&private_key);
	libless_partial_clean(&partial_key);
	libless_secret_clean(&secret);
	libless_public_clean(&public_key);
	libless_master_clean(&master_key);
	libless_parameters_clean(&parameters);
	libless_clean(&env);
}
