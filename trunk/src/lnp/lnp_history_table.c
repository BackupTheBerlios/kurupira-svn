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
 * @file lnp_history_table.c
 * @ingroup lnp
 */

#include <stdlib.h>

#include <pthread.h>

#include "lnp_link.h"
#include "lnp_history_table.h"

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

void lnp_history_insert(history_entry_t *entry, int session) {
	/* O(1) */
	entry->history[entry->end] = session;
	entry->end = (entry->end+1) % HISTORY_SIZE;
	if (entry->end == entry->begin) {
		entry->begin = (entry->begin+1) % HISTORY_SIZE;
	}
}
/******************************************************************************/
int lnp_history_get_route(history_entry_t *entry, int session_from) {
	/* O(n) */
	double aux;
	int used_size;
	int tmp;
	int i;
	
retry_label:	
	
	aux = (double)rand()/RAND_MAX;
	used_size = (entry->end - entry->begin + HISTORY_SIZE) % HISTORY_SIZE;
	tmp = (int)(aux*used_size) + entry->begin;
	tmp %= HISTORY_SIZE;
	
	/* Try from tmp to the end */
	for (i = tmp; i != entry->end; i = (i+1)%HISTORY_SIZE) {
		if (entry->history[i] != session_from) {
			if (!lnp_is_session_active(entry->history[i])) {
				lnp_history_disconnect(entry, entry->history[i]);
				goto retry_label;
			}
			return entry->history[i];
		}
	}
	/* Try from begin to tmp */
	for (i = entry->begin; i != tmp; i = (i+1)%HISTORY_SIZE) {
		if (entry->history[i] != session_from) {
			if (!lnp_is_session_active(entry->history[i])) {
				lnp_history_disconnect(entry, entry->history[i]);
				goto retry_label;
			}
			return entry->history[i];
		}
	}

	return LNP_HISTORY_NO_ROUTE;
}
/******************************************************************************/
void lnp_history_disconnect(history_entry_t *entry, int session) {
	/* O(n) */
	int i;
	int pos;

	pos = entry->begin;
	for (i = entry->begin; i != entry->end; i = (i+1) % HISTORY_SIZE) {
		if (entry->history[i] != session) {
			entry->history[pos] = entry->history[i];
			pos = (pos+1) % HISTORY_SIZE;	
		}
	}
	entry->end = pos;	
}
/******************************************************************************/
void lnp_history_erase(history_entry_t *entry) {
	/* O(1) */
	entry->end = entry->begin = 0;
}
/******************************************************************************/
/*int main() {
	int i;
	int last = -1;
	sranddev();
	
	history_entry_t history_table;
	lnp_history_erase(&history_table);
	
	for (i=0; i<100; i++) {
		double aux = (double)rand()/RAND_MAX;
		int tmp = (int)(aux*10);
		int j;
		if (i >= HISTORY_SIZE) {
			tmp = last;
		}
		lnp_history_insert(&history_table, tmp);
		for (j=history_table.begin; j!=history_table.end; 
				j=(j+1)%HISTORY_SIZE) {
			printf("%2d ", history_table.history[j]);		
		}
		last = lnp_history_get_route(&history_table,2);
		printf(" ROUTE: +%d\n", last);
		if (i%10==0 && last!=-1) {
			lnp_history_disconnect(&history_table, last);
		}

		if (i==98) {
			lnp_history_erase(&history_table);
		}
	}
}*/
