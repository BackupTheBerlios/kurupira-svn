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

#include <string.h> 
#include <stdlib.h>

#include <pthread.h>

#include <libfreedom/liblog.h>

#include "lnp.h"
#include "lnp_id.h"
#include "lnp_routing_table.h"
#include "lnp_routing_policy.h"
#include "lnp_collision_table.h"

/**
 * @file lnp_routing_policy.c
 * @ingroup lnp
 */

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * 
 */
static void handle_id_from(net_id_t id_from, int session_from);

/*
 * 
 */
static int get_next_session(net_id_t id_to, int session_from);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int lnp_routing_handle(net_id_t id_from, net_id_t id_to, u_char *packet_hash, 
		u_char packet_flags, int session_from) {
	int collision = lnp_handle_collision(packet_hash, packet_flags);
	if (collision != NO_COLLISION) {
		return LNP_ROUTE_DROP;
	}
	
	handle_id_from(id_from, session_from);

	if (memcmp(id_to, my_id, NET_ID_LENGTH) == 0) {
		return LNP_ROUTE_RECEIVE;	
	}
	
	return get_next_session(id_to, session_from);
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

void handle_id_from(net_id_t id_from, int session_from) {
	if (session_from < 0 || session_from >= 256) {
		return;	
	}
	int routing_entry_index = lnp_routing_entry_lock(id_from);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		/* TODO otimizar isso aki: call{lnp_add_id + lnp_routing_entry_lock}*/
		routing_entry_index = lnp_add_id(id_from);
		routing_entry_index = lnp_routing_entry_lock(id_from);
	}
	if (routing_entry_index != LNP_LOOKUP_ERROR) {
		history_entry_t * history_entry 
				= &routing_table[routing_entry_index].history;
		lnp_history_insert(history_entry, session_from);
		lnp_routing_entry_unlock(routing_entry_index);
	}
}
/******************************************************************************/
int get_next_session(net_id_t id_to, int session_from) {
	int routing_entry_index = lnp_routing_entry_lock(id_to);
	if (routing_entry_index != LNP_LOOKUP_ERROR) {
		history_entry_t * history_entry 
				= &routing_table[routing_entry_index].history;
		int session_to;
		session_to = lnp_history_get_route(history_entry, session_from);
		lnp_routing_entry_unlock(routing_entry_index);
		if (session_to == LNP_HISTORY_NO_ROUTE) {
			if (session_from < 0 || session_from >= 256) {
				return LNP_ROUTE_BROADCAST;
			} else {
				return LNP_ROUTE_BACK_WITH_ERROR;
			}
		} else {
			return session_to;	
		}
	}
	return LNP_ROUTE_BACK_WITH_ERROR;	
}
/******************************************************************************/
