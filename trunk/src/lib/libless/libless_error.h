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
 * @file libless_error.h
 * 
 * Error codes and interface of error management functions.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_ERR_H_
	#define _LIBLESS_ERR_H_

	/* @{ */
	/**
	 * Possible error code generated by the library.
	 */
	#define REASON_MEMORY				"not enough memory"
	#define REASON_CURVE_PARAMETERS	"invalid curve parameters"
	#define REASON_INVALID_ID			"invalid user identifier"
	#define REASON_HASH				"error in hash function"
	#define REASON_CIPHER				"error in (de)cipher function"
	#define REASON_PAIRING			"error in pairing computation"
	#define REASON_POINT_INFINITY		"point at infinity"
	#define REASON_ADDITION			"error in point addition"
	#define REASON_DOUBLING			"error in point doubling"
	#define REASON_QUADRATIC			"error in quadratic arithmetic"
	#define REASON_LUCAS				"error in lucas sequence computation"
	#define REASON_EXPANSION			"error in pairing expansion"
	#define REASON_COMPRESSION		"error in pairing compression"
	#define REASON_CIPHER				"error in (de)cipher function"
	#define REASON_DECRYPTION			"ciphertext can't be decrypted"
	#define REASON_OPENSSL			"OpenSSL error"
	/* @} */

	#undef ERROR_CONTEXT
	/**
	 * The context to use if an error occurs.
	 */
	#define ERROR_CONTEXT 		env

	#undef ERROR_CODE
	/**
	 * The error code to use if an error occurs.
	 */
	#define ERROR_CODE			LIBLESS_ERROR

	#undef ERROR_PRINT
	/**
	 * The printing function to use if an error occurs.
	 */
	#define ERROR_PRINT			liberror_complete_err

	#undef ERROR_PRINT_ALL
	/**
	 * The detailed printing function to use if an error occurs.
	 */
	#define ERROR_PRINT_ALL		liberror_complete_error

	#undef ERROR_CALLBACK
	/**
	 * The error callback to use if an error occurs.
	 */
	#define ERROR_CALLBACK	ERR_print_errors_fp(stderr);goto end;

#endif /* !_LIBLESS_ERR_H_ */
