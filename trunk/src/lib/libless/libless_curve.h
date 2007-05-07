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
 * @file libless_curve.h
 * 
 * Non-supersingular elliptic curve parammeters.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_CURVE_H_
	#define _LIBLESS_CURVE_H_

	/**
	 * @name Curve
	 * Chosen elliptic curve.
	 */
	/*@{ */
	/** 
	 * Parameter that describe the chosen curve \f$ y^2 = x^3-3x+b \bmod{p} \f$ 
	 * with \f$ n=\#E(\mathbb{F}_p) \f$ and a subgroup of points with the prime 
	 * order \f$ r=2^{159}+2^{17}+1 \f$ and cofactor \f$ h \f$. The prime number 
	 * \f$ p \f$ is supposed to be congruent to \f$3 \bmod{4}\f$.
	 */
	#define CURVE_P "DF9BD3ED0034174E54597AA4E2AB033D21C7F6F1AFDD080D4708BC67CA"\
		"C2AED554FE43F3DA7CD547ED458502C46356BB2A76688DDF064094EBE7785EDE2E413F"

	#define CURVE_A "DF9BD3ED0034174E54597AA4E2AB033D21C7F6F1AFDD080D4708BC67CA"\
		"C2AED554FE43F3DA7CD547ED458502C46356BB2A76688DDF064094EBE7785EDE2E413C"

	#define CURVE_B "CFEC8DDB4E226F34828D4F9B30571BB52E14D1611FA34031423862B3AC"\
		"B179102A1C152E860FC993A87999CB6A8539516C04950344270037ABC0905175FD47E"

	#define CURVE_H "1BF37A7DA00682E9CA8B2F549C556067A4388F10141E2BEC5D2CE78CA6"\
		"EF85DBB48606FEFE400661EDE015EF6"

	#define CURVE_R "8000000000000000000000000000000000020001"

	#define P_OVER_R "1BF37A7DA00682E9CA8B2F549C556067A4388F10141E2BEC5D2CE78CA"\
		"6EF85DBF05676CCF69E2C1025BAE4140"
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

	#define TWISTED_B	"-" CURVE_B

	#define TWISTED_P	CURVE_P

	#define TWISTED_H "1BF37A7DA00682E9CA8B2F549C556067A4388F10141E2BEC5D2CE78"\
		"CA6EF85DC2C26E69AEEFC51BE5D95B238A"
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

#endif /* !_LIBLESS_CURVE_H_ */
