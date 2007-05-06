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
 * @file libless_timing.h
 * 
 * Timing functions.
 * 
 * @version $Header$
 * @ingroup libless
 */

#ifndef _LIBLESS_TIMING_H_
	#define _LIBLESS_TIMING_H_

	#ifdef __linux__
		#define CLOCK	CLOCK_PROCESS_CPUTIME_ID
	#endif

	#ifdef FREEBSD
		#define CLOCK	CLOCK_PROF
	#endif

	/**
	 * Initializes the timing support.
	 */
	#define TIMING_INIT()												\
			struct timespec _t0, _t1;									\
			long int _result;

	/**
	 * Records the timing before execution.
	 */
	#define TIMING_BEFORE()											\
			clock_gettime(CLOCK, &_t0);

	/**
	 * Records the timing after execution.
	 */
	#define TIMING_AFTER()											\
			clock_gettime(CLOCK, &_t1);

	/**
	 * Computes the timing and prints the info in microseconds.
	 * 
	 * @param[in] FUNCTION     - the function executed.
	 */
	#define TIMING_COMPUTE(FUNCTION)										\
		_result = ((long)_t1.tv_sec - (long)_t0.tv_sec) * 1000000;		\
		_result += (_t1.tv_nsec - _t0.tv_nsec) / 1000;						\
		printf("TIMING: %s time: %ld microsec\n", #FUNCTION, _result);

	/**
	 * Computes the timing of n executions and prints the info in microseconds.
	 * 
	 * @param[in] FUNCTION     - the function executed.
	 */
	#define TIMING_COMPUTE_N(FUNCTION,TIMES)								\
		_result = ((long)_t1.tv_sec - (long)_t0.tv_sec) * 1000000;		\
		_result += (_t1.tv_nsec - _t0.tv_nsec) / 1000;						\
		printf("TIMING: %s time: %ld microsec\n", #FUNCTION, _result/TIMES);


	#ifndef WITH_TIMING
		#undef TIMING_INIT
		#undef TIMING_BEFORE
		#undef TIMING_AFTER
		#undef TIMING_COMPUTE
		#define TIMING_INIT() /* empty */
		#define TIMING_BEFORE() /* empty */
		#define TIMING_AFTER() /* empty */
		#define TIMING_COMPUTE(FUNCTION) /* empty */
	#endif

#endif /* !_LIBLESS_TIMING_H_ */
