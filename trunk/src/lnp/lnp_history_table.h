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
 * @file lnp_history_table.h
 * @ingroup lnp
 */
 
#ifndef _LNP_HISTORY_TABLE_H_
#define _LNP_HISTORY_TABLE_H_

/**
 * 
 */
#define HISTORY_SIZE 16

/**
 * 
 */
#define LNP_HISTORY_NO_ROUTE (-1)

/**
 * 
 */
typedef struct {
	/*net_id id; TODO é necessario esse campo?*/
	u_char history[HISTORY_SIZE];
	u_int begin;
	u_int end;
	u_int last_remove_time; /* TODO falta implementar */
} history_entry_t;

/**
 * 
 */
void lnp_history_insert(history_entry_t *entry, int session);

/**
 * TODO (FUTURE) precisa para aumentar performance
 */
/*void lnp_history_insert_multiple(..., int count);*/

/**
 * TODO precisa desta funcao? ela foi definida na monog :(
 */
/*void lnp_history_remove(int history_entry_index, int session);*/

/**
 * TODO acho q este método é privado
 */
void lnp_history_disconnect(history_entry_t *entry, int session);

/**
 * 
 */
int lnp_history_get_route(history_entry_t *entry, int session_from);

/**
 * 
 */
void lnp_history_erase(history_entry_t *entry);

#endif /* !_LNP_HISTORY_TABLE_H_ */
