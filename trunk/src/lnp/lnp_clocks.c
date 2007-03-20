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
 * @file lnp_clocks.c
 * @ingroup lnp
 */

#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>

#include "lnp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

u_int local_delay;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

static int get_current_time();

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/	   

int lnp_clock_initialize() {
	sranddev();
	local_delay = rand();
	return LNP_OK;
}
/******************************************************************************/
u_short lnp_get_local_clock() {
	return (u_short)(get_current_time() + local_delay);
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int get_current_time() {
	struct timeval time;

	gettimeofday(&time, NULL);

	return (int)time.tv_sec*100 + time.tv_usec/10000000;
}
/******************************************************************************/
