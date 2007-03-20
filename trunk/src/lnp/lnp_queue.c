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
 * @file lnp_queue.c Implementations of functions used by the LLP modules to
 * 		provide the datagrams received to the upper layers.
 * @ingroup lnp
 */

#include <stdlib.h>
#include <string.h>

#include <util/util.h>
#include <util/util_queue.h>

#include <libfreedom/layer_net.h>
#include <libfreedom/liblog.h>

#include "lnp_queue.h"
#include "lnp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Size of the queue used to store received datagrams.
 */
#define LNP_QUEUE_RELIABLE_SIZE		64
#define LNP_QUEUE_UNRELIABLE_SIZE	64

/*
 * Queue used to store received datagrams
 */
static util_queue_t queues[2];

/*
 * 
 */
#define QUEUE_RELIABLE 		0
#define QUEUE_UNRELIABLE	1

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

inline int get_queue_index(u_char protocol);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int lnp_queue_initialize() {
	int return_value;
	
	return_value 
			= (util_initialize_queue(&queues[QUEUE_RELIABLE], 
					LNP_QUEUE_RELIABLE_SIZE) == UTIL_OK)
			&& (util_initialize_queue(&queues[QUEUE_UNRELIABLE], 
					LNP_QUEUE_UNRELIABLE_SIZE) == UTIL_OK);
					
	return (return_value ? LNP_OK : LNP_ERROR);
}
/******************************************************************************/
void lnp_queue_finalize() {
	util_finalize_queue(&queues[QUEUE_RELIABLE]);
	util_finalize_queue(&queues[QUEUE_UNRELIABLE]);
}
/******************************************************************************/ 
int lnp_enqueue_datagram(net_id_t from, u_char *datagram, int length, 
		u_char protocol) {
	int return_value;
	u_char *id = NULL;
	
	int queue_index = get_queue_index(protocol);
	if (queue_index == LNP_ERROR) {
		return LNP_ERROR;
	}
	
	id = (u_char *)malloc(sizeof(net_id_t));
	if (id == NULL) {
		return LNP_ERROR;
	}
	
	memcpy(id, from, sizeof(net_id_t));
	
	/* We are using the tag pointer to store the id. */
	return_value = util_enqueue(&queues[queue_index], 
			(void *)id, datagram, length);
	return (return_value == UTIL_OK ? LNP_OK : LNP_ERROR);
}
/******************************************************************************/
int lnp_dequeue_datagram(net_id_t from, u_char *datagram, int max, 
		u_char protocol) {
	int return_value;
	u_char *id = NULL;

	int queue_index = get_queue_index(protocol);
	if (queue_index == LNP_ERROR) {
		return LNP_ERROR;
	}
	
	return_value = util_dequeue(&queues[queue_index], (void **)&id, 
			datagram, max);
	/* We are using the tag pointer to store the id. */
	if (return_value != UTIL_ERROR) {
		memcpy(from, id, sizeof(net_id_t));
		free(id);
		return return_value;
	}
	
	return LNP_ERROR;
}
/******************************************************************************/
int lnp_try_dequeue_datagram(net_id_t from, u_char *datagram, int max,
		u_char protocol) {
	int return_value;
	u_char *id = NULL;

	int queue_index = get_queue_index(protocol);
	if (queue_index == LNP_ERROR) {
		return LNP_ERROR;
	}
	return_value = util_try_dequeue(&queues[queue_index], (void **)&id, 
			datagram, max);
	/* We are using the tag pointer to store the id. */
	if (return_value != UTIL_ERROR) {
		memcpy(from, id, sizeof(net_id_t));
		free(id);
		return return_value;
	}
	
	return LNP_ERROR;
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int get_queue_index(u_char protocol) {
	if (protocol == LNP_PROTOCOL_RELIABLE) {
		return QUEUE_RELIABLE;	
	} else if (protocol == LNP_PROTOCOL_UNRELIABLE) {
		return QUEUE_UNRELIABLE;	
	} else  {
		return LNP_ERROR;	
	}
}
/******************************************************************************/
