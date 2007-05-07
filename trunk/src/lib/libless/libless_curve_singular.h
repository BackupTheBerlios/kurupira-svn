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
 * @file libless_curvess.h
 * 
 * Supersingular elliptic curve parameters.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_CURVE_SINGULAR_H_
	#define _LIBLESS_CURVE_SINGULAR_H_

	#include <liberror.h>

	/**
	 * @name Curve
	 * Chosen elliptic curve.
	 */
	/*@{ */
	/** 
	 * Parameter that describe the chosen curve \f$ y^2 = x^3+1 \bmod{p} \f$ 
	 * with \f$ n=\#E(\mathbb{F}_p) \f$ and a subgroup of points with the prime 
	 * order \f$ r=2^{159}+2^{17}+1 \f$ and cofactor \f$ h \f$. The prime number 
	 * \f$ p \f$ is supposed to be congruent to \f$3 \bmod{4}\f$.
	 */
	#define CURVE_P "8BA2A5229BD9C57CFC8ACEC76DFDBF3E3E1952C6B3193ECF5C571FB502"\
		"FC5DF410F9267E9F2A605BB0F76F52A79E8043BF4AF0EF2E9FA78B0F1E2CDFC4E8549B"

	#define CURVE_A "1"

	#define CURVE_B "0"

	#define CURVE_H "117454A4537B38AF9F9159D8EDBFB7E7C7C2E48760E930A461D5F451F9D"\
		"9210DC70095F4B241FF57F1BB0549C"

	#define CURVE_R "8000000000000000000000000000000000020001"

	#define P_OVER_R CURVE_H
	/*@} */

	/**
	 * @name Twisted curve
	 * Twisted elliptic curve.
	 */
	/*@{ */
	/** 
	 * Parameter that describe the twisted curve \f$ y^2= x^3-3x-b \bmod{p} \f$ 
	 * isomorphic to the chosen curve defined on the quadratic extension of the
	 * prime field.
	 */
	#define TWISTED_A	CURVE_A

	#define TWISTED_B	"0"

	#define TWISTED_P	CURVE_P

	#define TWISTED_H	CURVE_H
	/*@} */

	/**
	 * Size in bits of \f$ p \f$, the characteristic of the prime field.
	 */
	#define P_SIZE_BITS	512

	/**
	 * Size in bytes of \f$ p \f$, the characteristic of the prime field.
	 */
	#define P_SIZE_BYTES	((P_SIZE_BITS >> 3) + (P_SIZE_BITS % 8 ? 1 : 0))

	/**
	 * Size in bits of \f$ r \f$, the order of the subgroup of points.
	 */
	#define R_SIZE_BITS	160

	/**
	 * Size in bytes of \f$ r \f$, the order of the subgroup of points.
	 */
	#define R_SIZE_BYTES	((R_SIZE_BITS >> 3) + (R_SIZE_BITS % 8 ? 1 : 0))

	/**
	 * Length of a elliptic curve point in bytes (compressed form).
	 */
	#define POINT_SIZE_BYTES	(P_SIZE_BYTES + 1)

#endif /* !_LIBLESS_CURVE_SINGULAR_H_ */
