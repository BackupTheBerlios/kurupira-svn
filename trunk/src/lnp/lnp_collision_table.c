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
 * @file lnp_collision_table.c
 * @ingroup lnp
 */

#include <string.h>
#include <stdlib.h>

#include <pthread.h>

#include "lnp_collision_table.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * 
 */
#define COLLISION_TABLE_SIZE 0x100

/*
 * 
 */
typedef struct {
	u_char hash[COLLISION_HASH_LENGTH];
	u_char session_to;
} collision_entry_t;

/*
 * 
 */
static collision_entry_t collision_table[COLLISION_TABLE_SIZE];

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * 
 */
static u_int hash_function(u_char *packet_hash);

/*
 * 
 */
static int hash_cmp(u_int index, u_char *packet_hash);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/	   

int lnp_handle_collision(u_char *packet_hash, u_char packet_flags) {
	u_int index = hash_function(packet_hash);
	if (hash_cmp(index, packet_hash) == 0) {
		return collision_table[index].session_to;
	}
	memcpy(collision_table[index].hash, packet_hash, COLLISION_HASH_LENGTH);
	collision_table[index].session_to = 1; /* TODO implementar */
	return NO_COLLISION;
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

u_int hash_function(u_char *packet_hash) {
	return *((u_int*)packet_hash) % COLLISION_TABLE_SIZE;
}
/******************************************************************************/
int hash_cmp(u_int index, u_char *packet_hash) {
	return memcmp(collision_table[index].hash, packet_hash, 
			sizeof(collision_table[index].hash));
}
/******************************************************************************/
