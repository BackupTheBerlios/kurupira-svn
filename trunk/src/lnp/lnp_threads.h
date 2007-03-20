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
 * @file lnp_threads.h Headers of routines used to manipulate the LNP module
 * 		threads.
 * @ingroup lnp
 */

#ifndef _LNP_THREADS_H_
#define _LNP_THREADS_H_

/**
 * Creates the threads, condition variables and mutexes.
 * 
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_create_threads();

/**
 * Destroys the crated threads, condition variables and mutexes.
 */
void lnp_destroy_threads();

#endif /* !_LLP_THREADS_H_ */
