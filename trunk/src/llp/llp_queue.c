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
 * @file llp_queue.c Implementations of functions used by the LLP modules to
 * 		provide the datagrams received to the upper layers.
 * @ingroup llp
 */

#include <util/util.h>
#include <util/util_queue.h>

#include "llp_queue.h"
#include "llp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Size of the queue used to store received datagrams.
 */
#define LLP_QUEUE_SIZE	64

/*
 * Queue used to store received datagrams
 */
static util_queue_t queue;

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_queue_initialize() {
	int return_value;
	
	return_value = util_initialize_queue(&queue, LLP_QUEUE_SIZE);
	return (return_value == UTIL_OK ? LLP_OK : LLP_ERROR);
}
/******************************************************************************/
void llp_queue_finalize() {
	util_finalize_queue(&queue);
}
/******************************************************************************/ 
int llp_enqueue_datagram(int session, u_char *datagram, int length) {
	int return_value;
	
	/* We are using the tag pointer to store the session number. */
	return_value = util_enqueue(&queue, (void *)session, datagram, length);
	return (return_value == UTIL_OK ? LLP_OK : LLP_ERROR);
}
/******************************************************************************/
int llp_dequeue_datagram(int *session, u_char *datagram, int max) {
	int return_value;
	
	/* We are using the tag pointer to store the session number. */
	return_value = util_dequeue(&queue, (void **)session, datagram, max);
	return (return_value == UTIL_ERROR ? LLP_ERROR : return_value);
}
/******************************************************************************/
int llp_try_dequeue_datagram(int *session, u_char *datagram, int max) {
	int return_value;
	
	/* We are using the tag pointer to store the session number. */
	return_value = util_try_dequeue(&queue, (void **)session, datagram, max);
	return (return_value == UTIL_ERROR ? LLP_ERROR : return_value);
}
/******************************************************************************/
