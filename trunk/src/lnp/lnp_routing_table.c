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
 * @file lnp_routing_table.c
 * @ingroup lnp
 */

#include <string.h>
#include <stdlib.h> /* rand */
#include <pthread.h>

#include "lnp.h"
#include "lnp_routing_table.h"
#include "lnp_store.h"

/*============================================================================*/
/* Public data definitions.                                                   */
/*============================================================================*/

routing_entry_t routing_table[ROUTING_TABLE_SIZE];

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * 
 */
static pthread_mutex_t routing_table_mutex;

/*
 * 
 */
static pthread_mutex_t lnp_routing_entry_mutexes[ROUTING_TABLE_SIZE];

/*
 * 
 */
static pthread_cond_t lnp_routing_handshake_condition[ROUTING_TABLE_SIZE];

/*
 * 
 */
static int used_entries = 0;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * 
 */
static int slot_cmp(int routing_entry_index, net_id_t id);

/*
 * 
 */
static int find_id(net_id_t id);

/*
 * 
 */
static u_int hash_function(net_id_t id);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/	   

int lnp_routing_table_initialize() {
	int i;
	for (i = 0; i < ROUTING_TABLE_SIZE; i++) {
		pthread_mutexattr_t mta;
		if (pthread_mutexattr_init(&mta)!=0) {
			return LNP_ERROR;
		}
		if (pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE) != 0) {
			return LNP_ERROR;
		}
		if (pthread_mutex_init(&lnp_routing_entry_mutexes[i], &mta)!=0) {
			return LNP_ERROR;
		}
		if (pthread_cond_init(&lnp_routing_handshake_condition[i], NULL)!=0) {
			return LNP_ERROR;
		}
		routing_table[i].store_index = NULL_SLOT;
	}
	pthread_mutex_init(&routing_table_mutex, NULL);
	lnp_key_store_initialize();
	
	return LNP_OK;
}
/******************************************************************************/
int lnp_lookup_id(net_id_t id) {
	pthread_mutex_lock(&routing_table_mutex);
	u_int index = find_id(id);
	if (index == LNP_LOOKUP_ERROR) {
		pthread_mutex_unlock(&routing_table_mutex);
		return LNP_LOOKUP_ERROR;	
	}
	if (routing_table[index].is_used) {
		pthread_mutex_unlock(&routing_table_mutex);
		return index;
	}
	pthread_mutex_unlock(&routing_table_mutex);
	return LNP_LOOKUP_ERROR;
}
/******************************************************************************/
int lnp_add_id(net_id_t id) {
	pthread_mutex_lock(&routing_table_mutex);
	u_int index = find_id(id);
	/**
	 * We need to left one slot unused.
	 */
	if (used_entries == ROUTING_TABLE_SIZE-1) {
		pthread_mutex_unlock(&routing_table_mutex);
		return index;
	}
	if (!routing_table[index].is_used) {
		routing_table[index].is_used = 1;
		routing_table[index].store_index = NULL_SLOT;
		memcpy(routing_table[index].id, id, sizeof(net_id_t));
		used_entries++;
	}
	pthread_mutex_unlock(&routing_table_mutex);
	return index;
}
/******************************************************************************/
int lnp_remove_id(net_id_t id) {
	int j;
	int k;
	
	pthread_mutex_lock(&routing_table_mutex);
	u_int index = find_id(id);
	if (index == LNP_LOOKUP_ERROR || !routing_table[index].is_used) {
		pthread_mutex_unlock(&routing_table_mutex);
		return LNP_LOOKUP_ERROR;	
	}
	
	j = (index + 1) % ROUTING_TABLE_SIZE;
	while (routing_table[j].is_used) {
		k = hash_function(routing_table[j].id);
		if (((j>index) && (k<=index || k>j)) 
				|| ((j<index) && (k<=index && k>j))) { 
			memcpy(&routing_table[index], &routing_table[j], 
					sizeof(routing_entry_t));
			index = j;
		}
		j = (j + 1) % ROUTING_TABLE_SIZE;
	}

	routing_table[index].is_used = 0;
	used_entries--;
	pthread_mutex_unlock(&routing_table_mutex);
	return 1;
}
/******************************************************************************/
int lnp_routing_entry_lock(net_id_t id) {
	int routing_entry_index = lnp_lookup_id(id);
	if (routing_entry_index == LNP_LOOKUP_ERROR) {
		return LNP_LOOKUP_ERROR;	
	}
	pthread_mutex_lock(&lnp_routing_entry_mutexes[routing_entry_index]);
	
	/* avoid concurrency error */
	if (!routing_table[routing_entry_index].is_used) {
		pthread_mutex_unlock(&lnp_routing_entry_mutexes[routing_entry_index]);
		return LNP_LOOKUP_ERROR;	
	}
	
	return routing_entry_index;
}
/******************************************************************************/
void lnp_routing_entry_unlock(int routing_entry_index) {
	if ((routing_entry_index<0) || (routing_entry_index>=ROUTING_TABLE_SIZE)) {
		/* TODO: este if talvez seja desnecessario */
		return;	
	}
	pthread_mutex_unlock(&lnp_routing_entry_mutexes[routing_entry_index]);
}
/******************************************************************************/
void lnp_routing_entry_condwait(int routing_entry_index, int miliseconds) {
	struct timeval time;
	struct timespec delay;
	int ret;
	
	gettimeofday(&time, NULL);
	delay.tv_nsec = time.tv_usec * 1000 +
			(((long)miliseconds) % 1000) * 1000 * 1000;

	/* If nsec is bigger than a second. */
	if (delay.tv_nsec > 1000000000) {
		delay.tv_sec = time.tv_sec + delay.tv_nsec / 1000000000 +
				((long)miliseconds) / 1000;
		delay.tv_nsec %= 1000000000;
	} else {
		delay.tv_sec = time.tv_sec + miliseconds / 1000;
	}
	
	ret = pthread_cond_timedwait(
				&lnp_routing_handshake_condition[routing_entry_index],
				&lnp_routing_entry_mutexes[routing_entry_index], 
				&delay);
}
/******************************************************************************/
void lnp_routing_entry_signal(int routing_entry_index) {
	pthread_cond_broadcast(
			&lnp_routing_handshake_condition[routing_entry_index]);	
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int find_id(net_id_t id) {
	u_int first_hash = hash_function(id);
	u_int hash = first_hash;
	while (routing_table[hash].is_used 
			&& (slot_cmp(hash, id) != 0)) {
		hash = (hash + 1) % ROUTING_TABLE_SIZE;
		if (hash == first_hash) {
			return LNP_LOOKUP_ERROR;
		}
	}
	return hash;
}
/******************************************************************************/
u_int hash_function(net_id_t id) {
	/* TODO otimizar, usando & no lugar de % */
	return (*((u_int*)id)) % ROUTING_TABLE_SIZE;
}
/******************************************************************************/
int slot_cmp(int routing_entry_index, net_id_t id) {
	/* TODO otimizar: comparar a partir do 4o byte, pois 
	 * o hash jah sao os 4 primeiros */
	int r = memcmp(routing_table[routing_entry_index].id, id, sizeof(net_id_t));
	return r;
}
/******************************************************************************/
