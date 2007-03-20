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
 * @file lnp_threads.c Implementations of routines used to handle the LLP module
 * 		threads.
 * @ingroup lnp
 */
 
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>

#include <libfreedom/layer_link.h>
#include <libfreedom/liblog.h>
#include <libfreedom/layers.h>

#include "lnp.h"
#include "lnp_link.h"
 
/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Thread that will listen in UDP socket.
 */
static pthread_t listen_thread;

/*
 * 
 */
static int finish_execution = 0;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * Function to be executed by the listen_thread.
 */
static void *run_listen_link();

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int lnp_create_threads() {
	/* Thread to listen packets. */
	if (pthread_create(&listen_thread, NULL, run_listen_link, NULL)) {
		liblog_error(LAYER_LINK, "error creating thread: %s.", strerror(errno));
		return LNP_ERROR;
	}
	
	finish_execution = 0;
	
	return LNP_OK;
}
/******************************************************************************/
void lnp_destroy_threads() {
	
	finish_execution = 1;
}

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

void *run_listen_link() {

	lnp_listen_link();
	pthread_exit(NULL);
		
	return LNP_OK;
}
/******************************************************************************/
