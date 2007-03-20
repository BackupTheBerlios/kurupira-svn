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
 * @file libless_types.h
 * 
 * Interface of the type management routines.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_TYPES_H_
	#define _LIBLESS_TYPES_H_

	#include <openssl/ec.h>
	#include <openssl/bn.h>

	/**
	 * Type that represents the public system parameters of a particular CL-PKC 
	 * instantiation.
	 */
	typedef struct {
		EC_POINT *public;		/**< The public key of the central authority. */
		EC_POINT *generator1;	/**< The generator of the first group. */
		EC_POINT *generator2;	/**< The generator of the first group. */
		EC_GROUP *group1;		/**< The group of points in the curve. */
		EC_GROUP *group2;		/**< The group of points of the twisted curve.*/
		BIGNUM *pairing;		/**< The result of e(generator1, generator2). */
		BIGNUM *prime;			/**< The prime order of the finite field. */
		BIGNUM *factor;			/**< The factor of the curve order. */
	} libless_params_t;

	/**
	 * Type that represents a master key generated by the KGC.
	 */
	typedef BIGNUM *libless_master_t;
	
	/**
	 * Type that represents a secret value known only to the users.
	 */
	typedef BIGNUM *libless_secret_t;
	
	/**
	 * Type that represents a partial private key generated by the KGC.
	 */
	typedef EC_POINT *libless_partial_t;
	
	/**
	 * Type that represents a public key generated by the user.
	 */
	typedef BIGNUM *libless_public_t;
	
	/**
	 * Type that represents a private key computed by the user.
	 */
	typedef struct {
		libless_secret_t secret;		/**< Secret only known by the user. */
		libless_partial_t partial;	/**< Partial key extracted. */
	} libless_private_t;
	
	/**
	 * Type that represents signature data.
	 */
	typedef struct {
		unsigned char *image;		/**< Image of the session key. */
		int image_len;				/**< Length of image in bytes. */
		unsigned char *hash;		/**< Hash of the message and session key. */
		int hash_len;				/**< Length of hash in bytes. */
	} libless_signature_t;

	/**
	 * Initializes a set of public parameters.
	 * 
	 * @param[out] parameters		- the parameters to initialize
	 */
	void libless_parameters_init(libless_params_t *parameters);

	/**
	 * Frees the resources associated with a set of public parameters.
	 * 
	 * @param[in,out] parameters	- the parameters to free
	 */
	void libless_parameters_clean(libless_params_t *parameters);

	/**
	 * Initializes a master key.
	 * 
	 * @param[out] master_key		- the master key to initialize
	 */
	void libless_master_init(libless_master_t *master_key);

	/**
	 * Frees the resources associated with a master key.
	 * 
	 * @param[in,out] master_key	- the master key to free
	 */
	void libless_master_clean(libless_master_t *master_key);

	/**
	 * Initializes a partial private key.
	 * 
	 * @param[out] partial_key		- the partial private key to initialize
	 */
	void libless_partial_init(libless_partial_t *partial_key);

	/**
	 * Frees the resources associated with a private partial key.
	 * 
	 * @param[in,out] partial_key	- the partial private key to free
	 */
	void libless_partial_clean(libless_partial_t *partial_key);

	/**
	 * Initializes a user secret.
	 * 
	 * @param[out] secret			- the user secret to initialize
	 */
	void libless_secret_init(libless_secret_t *secret);

	/**
	 * Frees the resources associated with a user secret.
	 * 
	 * @param[in,out] secret		- the user secret to free
	 */
	void libless_secret_clean(libless_secret_t *secret);

	/**
	 * Initializes a user public key.
	 * 
	 * @param[out] public_key		- the public key to initialize
	 */
	void libless_public_init(libless_public_t *public_key);

	/**
	 * Frees the resources associated with a user public key.
	 * 
	 * @param[in,out] public_key	- the public key to free
	 */
	void libless_public_clean(libless_public_t *public_key);

	/**
	 * Initializes a user private key.
	 * 
	 * @param[out] private_key		- the private key to initialize
	 */	
	void libless_private_init(libless_private_t *private_key);

	/**
	 * Frees the resources associated with a user private key.
	 * 
	 * @param[in,out] private_key	- the private key to free
	 */
	void libless_private_clean(libless_private_t *private_key);

	/**
	 * Initializes a signature.
	 * 
	 * @param[out] signature		- the signature to initialize
	 */
	void libless_signature_init(libless_signature_t *signature);

	/**
	 * Frees the resources associated with a signature.
	 * 
	 * @param[in,out] signature		- the signature to free
	 */
	void libless_signature_clean(libless_signature_t *signature);

#endif /* !_LIBLESS_TYPES_H_ */
