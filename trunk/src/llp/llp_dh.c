/*
 * Copyright (C) 2004 by
 * - Diego "iamscared" Aranha <iamscared[at]users.sourceforge.net> &
 * - Edans "snade" Flavius <snade[at]users.sourceforge.net>
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
 * @file llp_dh.c Implementation of routines used in Diffie & Hellman key
 * 		agreement.
 * @ingroup llp
 */

#include <sys/types.h>

#include <libfreedom/layers.h>
#include <libfreedom/layer_link.h>
#include <libfreedom/liblog.h>
#include <util/util.h>

#include "llp.h"
#include "llp_packets.h"
#include "llp_sessions.h"
#include "llp_dh.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/**
 * Defines the element the generator of the Zp ring used in modular
 * exponentiations calculations.
 */
#define LLP_GROUP_GENERATOR	2

/*
 * Prime number used in Diffie & Hellman modular exponentiation caculations.
 * It is the 2048 bit MODP group (id 14), specified in RFC 3526.
 */
static u_char prime[] = {
		0x00, 0x00, 0x01, 0x01,	/* Size of number. */
		0x00,					/* Signal byte. */
		0xFF, 0xFF, 0XFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xC9, 0xFD, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x88, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
		0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
		0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x68,
		0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0xB9, 0x9F, 0xA5,
		0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
		0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
		0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
		0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
		0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
		0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
		0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
		0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
		0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
		0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
		0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * Computes (y = g^x mod p), with values for g and p fixed.
 */
static int compute_y(mpint y, mpint x);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/	   

int llp_compute_dh_params(mpint x, mpint y) {

	/* Exponent x is a string of pseudo-random bytes. */
	if (util_rand_mpint(x, LLP_X_LENGTH - MPINT_SIZE_LENGTH -
			MPINT_SIGNAL_LENGTH) == UTIL_ERROR) {
		liblog_error(LAYER_LINK, "error generating random exponent.");
		return LLP_ERROR;
	};
	liblog_debug(LAYER_LINK, "random exponent generated.");

	/* Computing (y = g^x mod p)	for Diffie & Hellman. */
	if (compute_y(y, x) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error computing y parameter.");
		return LLP_ERROR;
	}
	liblog_debug(LAYER_LINK, "y parameter computed.");

	return LLP_OK;
}
/******************************************************************************/
int llp_compute_dh_secret(mpint z, mpint y, mpint x) {
	BIGNUM *z_bignum, *y_bignum, *x_bignum, *p_bignum;
	BN_CTX *context = NULL;
	int length;
	int return_value;
	
	return_value = LLP_OK;
	z_bignum = BN_new();
	y_bignum = BN_mpi2bn(y, MPINT_LENGTH(y) + MPINT_SIZE_LENGTH, NULL);
	x_bignum = BN_mpi2bn(x, MPINT_LENGTH(x) + MPINT_SIZE_LENGTH, NULL);
	
	p_bignum = BN_mpi2bn(prime, MPINT_LENGTH(prime) + MPINT_SIZE_LENGTH, NULL);
	
	if (z_bignum == NULL || y_bignum == NULL || x_bignum == NULL ||
			p_bignum == NULL) {
		liblog_error(LAYER_LINK, "error allocating BIGNUMs.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	/* Creating the context. */
	context = BN_CTX_new();
	BN_CTX_init(context);

	/* Computing y_in^x mod p. */
	BN_mod_exp(z_bignum, y_bignum, x_bignum, p_bignum, context);
	length = BN_bn2mpi(z_bignum, NULL);
	if (length > LLP_Z_LENGTH) {
		liblog_error(LAYER_LINK, "computed z is too large.");
		return_value = LLP_ERROR;
		goto return_label;
	}

	/* Converting bignum z to mpint z. */
	BN_bn2mpi(z_bignum, z);

return_label:

	BN_free(z_bignum);
	BN_free(y_bignum);
	BN_free(x_bignum);
	BN_free(p_bignum);
	BN_CTX_free(context);	
	return return_value;
}
/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/	   

int compute_y(mpint y, mpint x) {
	/* Bignum representations. */
	BIGNUM  *y_bignum, *g_bignum, *x_bignum, *p_bignum;
	BN_CTX *context = NULL;
	int length;
	int return_value;
	
	return_value = LLP_OK;
	y_bignum = BN_new();
	g_bignum = BN_new();
	x_bignum = BN_mpi2bn(x, MPINT_LENGTH(x) + MPINT_SIZE_LENGTH, NULL);
	p_bignum = BN_mpi2bn(prime, MPINT_LENGTH(prime) + MPINT_SIZE_LENGTH, NULL);

	if (y_bignum == NULL || g_bignum == NULL || x_bignum == NULL ||
			p_bignum == NULL) {
		liblog_error(LAYER_LINK, "error allocating BIGNUMs.");
		return_value = LLP_ERROR;
		goto return_label;
	}

	BN_set_word(g_bignum, LLP_GROUP_GENERATOR);

	/* Creating the context. */
	context = BN_CTX_new();
	BN_CTX_init(context);
		
	/* Computing (g^x mod p). */
	BN_mod_exp(y_bignum, g_bignum, x_bignum, p_bignum, context);

	length = BN_bn2mpi(y_bignum, NULL);
	if (length > LLP_Y_LENGTH) {
		liblog_error(LAYER_LINK, "computed y is too large.");
		return_value = LLP_ERROR;
		goto return_label;
	}

	/* Cnverting bignum y_out to mpint y_out. */
	BN_bn2mpi(y_bignum, y);

return_label:

	BN_free(y_bignum);
	BN_free(g_bignum);
	BN_free(x_bignum);
	BN_free(p_bignum);
	BN_CTX_free(context);	
	return LLP_OK;
}
/******************************************************************************/
