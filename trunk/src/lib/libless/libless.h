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
 * @defgroup libless libless, the cryptographic module
 */

/**
 * @file libless.h
 * 
 * Interface of the Certificateless Public Key Cryptography Module.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_H_
	#define _LIBLESS_H_

	#include <liberror.h>

	#include "libless_types.h"

	/**
	 * Constant indicating success.
	 */
	#define LIBLESS_OK		1

	/**
	 * Constant indicating error.
	 */
	#define LIBLESS_ERROR	0

	#ifdef WITH_SUPERSINGULAR

		#include "libless_curvess.h"

	#else

		#include "libless_curve.h"

	#endif

	/**
	 * Type that describes the library environment.
	 */
	typedef error_t libless_t;

	/**
	 * Initializes the library.
	 * 
	 * @param[out] env      - the library context
	 */
	void libless_init(libless_t *env);

	/**
	 * Finalizes the library.
	 * 
	 * @param[in,out] env   - the library context.
	 */
	void libless_clean(libless_t *env);

#endif /* !_LIBLESS_H_ */
