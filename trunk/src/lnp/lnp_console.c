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
 * @file lnp_console.c
 * @ingroup lnp
 */

#include <string.h> 
#include <stdio.h> 
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>

#include <libfreedom/layer_console.h>

#include "lnp.h"
#include "lnp_id.h"
#include "lnp_data.h"
#include "lnp_store.h"
#include "lnp_handshake.h"
#include "lnp_routing_table.h"

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * Concatenates the format string to the out buffer.
 * 
 * @param out The out buffer. The format string will be concatenated to this
 * 		parameter.
 * @param buffer_len Maximum length allowed to write at out buffer.
 * @param format The format string.
 * @param ... The arguments to the format string.
 */
static void console_printf(char *out, int buffer_len, const char * format, ...);

/*
 * Cancatenates an hex dump to the out buffer.
 * 
 * @param out The out buffer. The format string will be concatenated to this
 * 		parameter.
 * @param buffer_len Maximum length allowed to write at out buffer.
 * @param data The data to be dumped.
 * @param len How many bytes will be dumped from data.
 */
static void console_dump(char *out, int buffer_len, u_char *data, int len);

/**
 * 
 */
static void console_print_id(char *out, int buffer_len, net_id_t);

/**
 * 
 */
static void parse_id(net_id_t id, char *tok);

/*
 * LNP implementation for console_execute_command.
 */
static void lnp_console_execute_command(char *out_buffer, int buffer_len, 
		int function_id, char *args);
		
/*
 * LNP implementation for console_get_command_list.
 */
static void lnp_console_get_command_list(command_t **command_arg, int *size);

/*
 * Execute COMMAND_ID command.
 */
static void console_id(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_WRITE command.
 */
static void console_write(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_READ command.
 */
static void console_read(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_CONNECTIONS command.
 */
static void console_connections(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_FLUSH command.
 */
static void console_flush(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_HISTORY command.
 */
static void console_history(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_CONNECT command.
 */
static void console_connect(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_KEYS command.
 */
static void console_print_keys(char *out_buffer, int buffer_len, char *args);

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * console interface struct.
 */
static layer_console_t layer_console = {
	lnp_console_execute_command,
	lnp_console_get_command_list
};

/*
 * Command identifiers.
 */
#define COMMAND_ID				1
#define COMMAND_WRITE			2
#define COMMAND_READ			3
#define COMMAND_FLUSH			4
#define COMMAND_CONNECTIONS		5
#define COMMAND_HISTORY			6
#define COMMAND_CONNECT			7
#define COMMAND_KEYS			8

/*
 * All available commands to link stub module.
 */
static command_t commands[] = {
	{COMMAND_ID, "id", "[id]"
			". output your id in base 16."},
	{COMMAND_WRITE, "write", "[write <id> <msg>]"
			". send a message to <id> using LNP_PROTOCOL_UNRELIABLE."},
	{COMMAND_READ, "read", "[read]"
			". read the next packet received from LNP_PROTOCOL_UNRELIABLE."},
	{COMMAND_FLUSH, "flush", "[flush]"
			". dispose all enqueued messages."},
	{COMMAND_CONNECTIONS, "connections", "[connections]"
			". output connections status."},
	{COMMAND_HISTORY, "history", "[history <id>]"
			". output the history for some ID."},
	{COMMAND_CONNECT, "connect", "[connect <id>]"
			". connect to some ID."},
	{COMMAND_KEYS, "keys", "[keys <id>]"
			". show keys negaciated with some ID."},
};

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

layer_console_t *get_console_interface() {
	return &layer_console;
}
/******************************************************************************/
static void lnp_console_execute_command(char *out_buffer, int buffer_len, 
		int function_id, char *args) {
	switch (function_id) {
		case COMMAND_ID:
			console_id(out_buffer, buffer_len, args);
			break;
		case COMMAND_WRITE:
			console_write(out_buffer, buffer_len, args);
			break;
		case COMMAND_READ:
			console_read(out_buffer, buffer_len, args);
			break;
		case COMMAND_FLUSH:
			console_flush(out_buffer, buffer_len, args);
			break;
		case COMMAND_CONNECTIONS:
			console_connections(out_buffer, buffer_len, args);
			break;
		case COMMAND_HISTORY:
			console_history(out_buffer, buffer_len, args);
			break;
		case COMMAND_CONNECT:
			console_connect(out_buffer, buffer_len, args);
			break;
		case COMMAND_KEYS:
			console_print_keys(out_buffer, buffer_len, args);
			break;
	}
}
/******************************************************************************/
static void lnp_console_get_command_list(command_t **command_arg, int *size) {
	*command_arg = commands;
	*size = sizeof(commands);	
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

void console_id(char *out_buffer, int buffer_len, char *args) {
	console_printf(out_buffer, buffer_len, "ID: ");
	console_print_id(out_buffer, buffer_len, my_id);
	console_printf(out_buffer, buffer_len, "\n");
}
/******************************************************************************/
void console_print_keys(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	net_id_t id;
	int store_index;
	
	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	parse_id(id, tok);

	int routing_entry = lnp_routing_entry_lock(id);
	if (routing_entry == NULL_SLOT) {
		console_printf(out_buffer, buffer_len, "no routing entry.\n");
		return;
	}
	store_index = routing_table[routing_entry].store_index;
	if (store_index == NULL_SLOT) {
		console_printf(out_buffer, buffer_len, "no keys.\n");
		return;
	}
	lnp_key_entry_t *entry = &lnp_key_store[store_index];
	if (entry->handshake_state == LNP_HANDSHAKE_CONNECTED) {
		console_printf(out_buffer, buffer_len, "   cipher_in_key:");
		console_dump(out_buffer, buffer_len, 
				entry->cipher_in_key,
				entry->cipher->key_length);

		console_printf(out_buffer, buffer_len, "   cipher_out_key:");
		console_dump(out_buffer, buffer_len, 
				entry->cipher_out_key,
				entry->cipher->key_length);

		console_printf(out_buffer, buffer_len, "   cipher_in_iv:");
		console_dump(out_buffer, buffer_len, 
				entry->cipher_in_iv,
				entry->cipher->iv_length);

		console_printf(out_buffer, buffer_len, "   cipher_out_iv:");
		console_dump(out_buffer, buffer_len, 
				entry->cipher_out_iv,
				entry->cipher->iv_length);

		console_printf(out_buffer, buffer_len, "   mac_in_key:");
		console_dump(out_buffer, buffer_len, 
				entry->mac_in_key, 
				entry->mac->key_length);

		console_printf(out_buffer, buffer_len, "   mac_out_key:");
		console_dump(out_buffer, buffer_len, 
				entry->mac_out_key, 
				entry->mac->key_length);
	} else {
		console_printf(out_buffer, buffer_len, "session not established yet\n");
	}
	
	lnp_routing_entry_unlock(routing_entry);
}
/******************************************************************************/
void console_connect(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	net_id_t id;

	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	parse_id(id, tok);
	
	if (lnp_connect(id) == NET_OK) {
		console_printf(out_buffer, buffer_len, "Connected.\n");
	} else {
		console_printf(out_buffer, buffer_len, "Error connecting.\n");
	}
}
/******************************************************************************/
void console_write(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	u_char *msg;
	net_id_t id;

	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	parse_id(id, tok);

	tok = strtok(NULL, " \n");
	if (tok == NULL) {
		return;
	}
	msg = (u_char*)tok;
	
	lnp_write(id, msg, strlen(tok)+1, LNP_PROTOCOL_UNRELIABLE);
	console_printf(out_buffer, buffer_len, "Message sent.\n");
}
/******************************************************************************/
void console_read(char *out_buffer, int buffer_len, char *args) {
	net_id_t id;
	int return_value;
	u_char buffer[1000]; // TODO, colocar constante FTU

	return_value = lnp_read(id, buffer, sizeof(buffer), LNP_PROTOCOL_UNRELIABLE);
	if (return_value == NET_ERROR) {
		console_printf(out_buffer, buffer_len, "Error reading.\n");
	} else {
		console_printf(out_buffer, buffer_len, 
				"Message read from id: ");

		console_print_id(out_buffer, buffer_len, id);
		console_printf(out_buffer, buffer_len, "\nMSG(%d): ", return_value);
		console_dump(out_buffer, buffer_len, buffer, return_value);
		console_printf(out_buffer, buffer_len, "\n");
	}
}
/******************************************************************************/
void console_connections(char *out_buffer, int buffer_len, char *args) {
	int i;

	console_printf(out_buffer, buffer_len, "%-40s %-15s\n", 
			"ID",
			"State");

	for (i = 0; i < ROUTING_TABLE_SIZE; i++) {
		routing_entry_t *routing_entry = &routing_table[i];
		u_int store_index = routing_entry->store_index;
		if (store_index == NULL_SLOT) {
			continue;
		}
		lnp_key_entry_t *entry = &lnp_key_store[store_index];

		console_print_id(out_buffer, buffer_len, routing_table[i].id);

		/*console_printf(out_buffer, buffer_len, "  %-10d %-10d", 
				entry->packets_sent,
				entry->packets_received);*/
				
		console_printf(out_buffer, buffer_len, " %-15s\n", 
				entry->handshake_state==LNP_HANDSHAKE_CLOSED?
					"CLOSED":
				entry->handshake_state==LNP_HANDSHAKE_CONNECTING?
					"CONNECTING":
				entry->handshake_state==LNP_HANDSHAKE_BEING_CONNECTED?
					"BEING CONNECTED":
				entry->handshake_state==LNP_HANDSHAKE_EXCHANGING_KEYS?
					"EXCHANGING KEYS":
				"CONNECTED");
	}
}
/******************************************************************************/
void console_flush(char *out_buffer, int buffer_len, char *args) {
	int return_value;
	
	return_value = lnp_flush(LNP_PROTOCOL_UNRELIABLE);
	console_printf(out_buffer, buffer_len, 
			"Messages flushed: %d.\n", return_value);
}
/******************************************************************************/
void console_history(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	net_id_t id;
	int j;

	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	parse_id(id, tok);

	int routing_entry = lnp_routing_entry_lock(id);
	if (routing_entry == NULL_SLOT) {
		console_printf(out_buffer, buffer_len, "no routing entry.\n");
		return;
	}
	history_entry_t *entry = &routing_table[routing_entry].history;
	if (entry->begin == entry->end) {
		console_printf(out_buffer, buffer_len, "[*EMPTY*]\n");		
	} else {
		console_printf(out_buffer, buffer_len, "sessions: ");
		for (j=entry->begin; j!=entry->end; j=(j+1)%HISTORY_SIZE) {
			console_printf(out_buffer, buffer_len, "[%2d]", entry->history[j]);		
		}
		console_printf(out_buffer, buffer_len, "[*END*]\n");
	}
	
	lnp_routing_entry_unlock(routing_entry);
}
/******************************************************************************/
void console_printf(char *out, int buffer_len, const char * format, ...) {

	char line[100];
    va_list ap;

    va_start(ap, format);
	vsnprintf(line, sizeof(line), format, ap);
    va_end(ap);
    
    strncat(out, line, buffer_len - strlen(out) - 1);
}
/******************************************************************************/
void console_dump(char *out, int buffer_len, u_char *data, int len) {
	int k;	
	for(k=0; k<len; k++) {
		if (k%16==0) console_printf(out, buffer_len, "\n");
		console_printf(out, buffer_len, " %02X", data[k]);
	}
	console_printf(out, buffer_len, "\n");
}
/******************************************************************************/
void console_print_id(char *out, int buffer_len, net_id_t id) {
	int i;
	for (i=0; i<sizeof(net_id_t); i++) {
		console_printf(out, buffer_len, "%02X", id[i]);
	}
}
/******************************************************************************/
void parse_id(net_id_t id, char *tok) {
	int i;
	for (i=0; tok[i] && i<NET_ID_LENGTH*2; i+=2) {
		int aux_1 = tok[i]>='A' ? (tok[i]-'A'+10) : (tok[i]-'0');
		int aux_2 = tok[i+1]>='A' ? (tok[i+1]-'A'+10) : (tok[i+1]-'0');
		id[i/2] = aux_1*16 + aux_2;
	}
}
/******************************************************************************/
