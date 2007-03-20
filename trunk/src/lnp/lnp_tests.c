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
 * @file 
 * @ingroup lnp
 */
 
#include <stdlib.h>

#include "lnp.h"
#include "lnp_store.h"
#include "lnp_routing_table.h"
#include "lnp_routing_policy.h"

int id_n = ROUTING_TABLE_SIZE;
net_id_t id[ROUTING_TABLE_SIZE];

void test_1() {
	int i;
	for (i=0; i<id_n; i++) {
		printf("lnp_lookup_id(%.20s) = 0x%X\n", id[i], lnp_lookup_id(id[i]));
		printf("   lnp_add_id(%.20s) = 0x%X\n", id[i], lnp_add_id(id[i]));
	}
}

void test_2() {
	int i;
	for (i=0; i<id_n; i++) {
		printf("lnp_lookup_id(%.20s) = 0x%X\n", id[i], lnp_lookup_id(id[i]));
		printf("lnp_remove_id(%.20s) = 0x%X\n", id[i], lnp_remove_id(id[i]));
		printf("lnp_lookup_id(%.20s) = 0x%X\n", id[i], lnp_lookup_id(id[i]));
	}
}

void test_3() {
	int i;
	int id_index;
	for (i=0; i<50; i++) {
		int store_entry_index;
		int id_index = (int)((double)rand()/RAND_MAX*20);
		
		/* lock routing entry */
		int routing_entry_index = lnp_routing_entry_lock(id[id_index]);
		if (routing_entry_index == LNP_LOOKUP_ERROR) {
			continue;	
		}
		
		if (routing_table[routing_entry_index].store_index == NULL_SLOT) {
			store_entry_index = lnp_key_store_new();
		} else {
			store_entry_index = routing_table[routing_entry_index].store_index;
			lnp_key_store_delete(store_entry_index);
			store_entry_index = NULL_SLOT;
		}
		routing_table[routing_entry_index].store_index = store_entry_index;
		printf("store[%.20s] = 0x%X\n", id[id_index], store_entry_index);

		/* unlock routing entry */
		lnp_routing_entry_unlock(routing_entry_index);
	}
}

void test_4() {
	int i;
	int id_index;
	for (i=0; i<10; i++) {
		int id_from = (int)((double)rand()/RAND_MAX*3);
		int id_to = (int)((double)rand()/RAND_MAX*3);
		int session_from = (int)((double)rand()/RAND_MAX*3);
		int session_to;
		u_char hash[20] = {3,2,1,i};
		
		session_to = lnp_routing_handle(id[id_from], id[id_to], hash, 0, session_from);
		/*#define LNP_ROUTE_RECIEVE (-1)
		#define LNP_ROUTE_BACK (-2)
		#define LNP_ROUTE_BACK_WITH_ERROR (-3)
		#define LNP_ROUTE_BROADCAST (-4)
		#define LNP_ROUTE_DROP (-5)*/
		
		printf("[%.5s...]->[%.5s...]   [%3d]->[%3d]\n", id[id_from], id[id_to], session_from, session_to);
	}	
}

int main() {
	int i, j;
	sranddev();
	lnp_routing_table_initialize();
	for (j=0; j<id_n; j++) {
		for (i=0; i<ID_LENGTH; i++) {
			id[j][i] = (u_char)(((double)rand()/RAND_MAX)*26)+'A';
		}
	}
	test_1();
	printf("--------\n");
	test_3();
	printf("--------\n");
	test_4();
	//test_2();
}
