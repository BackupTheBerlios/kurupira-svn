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
 * @file lnp_routing_table.h
 * @ingroup lnp
 */

#ifndef _LNP_ROUTING_TABLE_H_
#define _LNP_ROUTING_TABLE_H_

#include <pthread.h>


#include "lnp_collision_table.h"
#include "lnp_history_table.h"

/**
 * 
 */
#define ROUTING_TABLE_SIZE 0x100

#define LNP_LOOKUP_ERROR (-1)

/**
 * 
 */
typedef struct {
	u_char is_used;
	net_id_t id;
	u_int store_index;
	history_entry_t history;
	int clock_remote; /* TEM Q SER SIGNED, pq clock_remote pode ser negativo */
} routing_entry_t;

/**
 * 
 */
int lnp_routing_table_initialize();

/**
 * @return the routing entry index associated with this ID, or LNP_LOOKUP_ERROR
 * 		if the id was not found.
 */
int lnp_lookup_id(net_id_t id);

/**
 * TODO metodo necessario? nao basta o lookup?
 */
int lnp_add_id(net_id_t id);

/**
 * 
 */
int lnp_remove_id(net_id_t id);

/**
 * 
 */
int lnp_routing_entry_lock(net_id_t id);

/**
 * 
 */
void lnp_routing_entry_unlock(int routing_entry_index) ;

/**
 * 
 */
void lnp_routing_entry_condwait(int routing_entry_index, int miliseconds);

/**
 * 
 */
void lnp_routing_entry_signal(int routing_entry_index);

/**
 * 
 */
extern routing_entry_t routing_table[ROUTING_TABLE_SIZE];

#endif /* !_LNP_ROUTING_TABLE_H_ */
