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
 * Implementation of the Certificateless Public Key Cryptography module.
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

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/**
 * Length in bytes of the pseudo-random generator seed.
 */
#define SEED_LENGTH_BYTES	16

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void libless_init(libless_t *env) {
	env->code = LIBLESS_OK;
	memset(env->reason, 0, ERROR_LENGTH);

	RAND_load_file("/dev/random", SEED_LENGTH_BYTES);
	while (RAND_status() != 1) {
		RAND_load_file("/dev/random", SEED_LENGTH_BYTES);
	}

	ERR_load_crypto_strings();
}

void libless_clean(libless_t *env) {
	RAND_cleanup();

	ERR_free_strings();
}
