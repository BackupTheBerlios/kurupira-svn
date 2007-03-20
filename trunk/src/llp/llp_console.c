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
 * @file llp_console.c LLP implementation of console interface.
 * @ingroup llp
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <libfreedom/layer_console.h>
#include <libfreedom/layer_link.h>

#include "llp.h"
#include "llp_sessions.h"
#include "llp_packets.h"
#include "llp_handshake.h"
#include "llp_data.h"

/*============================================================================*/
/* Local data definitions.                                                    */
/*============================================================================*/

/*
 * Command identifiers.
 */
#define COMMAND_SESSIONS	1
#define COMMAND_KEYS		2
#define COMMAND_CONNECT		3
#define COMMAND_DISCONNECT	4
#define COMMAND_CLOSE		5
#define COMMAND_WRITE		6
#define COMMAND_READ		7
#define COMMAND_FLUSH		8
#define COMMAND_ALGORITHMS  9
#define COMMAND_DH_PARAMS  	10
#define COMMAND_STATISTICS	11

/*
 * All available commands to llp module.
 */
static command_t commands[] = {
	{COMMAND_SESSIONS, "sessions", 
			"[sessions]. Show session status."},
	{COMMAND_ALGORITHMS, "algorithms", 
			"[algorithms <level>]. Show session algorithms."},
	{COMMAND_DH_PARAMS, "dh", 
			"[dh <session_id>]. Show diffie-hellman parameters."},
	{COMMAND_KEYS, "keys", 
			"[keys <session_id>]. Show session keys."},
	{COMMAND_STATISTICS, "statistics", 
			"[statistics]. Show sessions statistics."},
	{COMMAND_CONNECT, "connect", 
			"[connect <ip> <port>]. Establish a new session to other host."},
	{COMMAND_DISCONNECT, "disconnect", 
			"[disconnect <session_id>]. Finalize an established session."},
	{COMMAND_CLOSE, "close", 
			"[close <session_id>]. Abort abruptly an established session."},
	{COMMAND_WRITE, "write", 
			"[write <session_id> <msg>]. Send a message through a session."},
	{COMMAND_READ, "read", 
			"[read <session_id>]. Reads a message from a session."},
	{COMMAND_FLUSH, "flush", 
			"[flush]. Disposes all enqueued messages."},
};

/*
 * console interface struct.
 */
static layer_console_t layer_console;

/*============================================================================*/
/* Local functions prototypes.                                                */
/*============================================================================*/

/*
 * Returns the command list of this console.
 * 
 * @command_arg exit parameter used to return command list.
 * @size exit parameter used to return command_arg size.
 */
static void console_get_command_list(command_t **command_arg, int *size);

/*
 * Executes a command of the layer.
 * 
 * @param out_buffer buffer to write output over it.
 * @param out_buffer size of the output buffer.
 * @function_id the function id to be executed.
 * @args argument to the function.
 */
static void console_execute_command(char *out_buffer, int buffer_len,
		int function_id, char *args);

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

/*
 * Execute COMMAND_ALGORITHMS command.
 */
static void console_print_algorithms(char *out_buffer, int buffer_len, 
		char *args);

/*
 * Execute COMMAND_DH_PARAMS.
 */
static void console_print_dh_params(char *out_buffer, int buffer_len, 
		char *args);

/*
 * Execute COMMAND_SESSIONS command.
 */
static void console_print_sessions(char *out_buffer, int buffer_len, 
		char *args);

/*
 * Execute COMMAND_STATISTICS command.
 */
static void console_print_statistics(char *out_buffer, int buffer_len, 
		char *args);

/*
 * Execute COMMAND_KEYS command.
 */
static void console_print_keys(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_CONNECT command.
 */
static void console_connect(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_DISCONNECT command.
 */
static void console_disconnect(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_CLOSE command.
 */
static void console_close_session(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_WRITE command.
 */
static void console_write_data(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_READ command.
 */
static void console_read_data(char *out_buffer, int buffer_len, char *args);

/*
 * Execute COMMAND_FLUSH command.
 */
static void console_flush(char *out_buffer, int buffer_len, char *args);

/*
 * Translates hostname to a sockaddr_in struct containing ip and port.
 * 
 * @param address the sockaddr_in struct where the address will be returned.
 * @param hostname the hostname string to be resolved.
 * @param port the value of the port field.
 * @return LLP_ERROR if the name can't be translated, LLP_OK otherwise.
 */
static int resolve_name(struct sockaddr_in *address, 
		char *hostname, int port);

/*============================================================================*/
/* Exported functions implementations.                                        */
/*============================================================================*/

layer_console_t *get_console_interface() {
	layer_console.console_execute_command =	console_execute_command;
	layer_console.console_get_command_list = console_get_command_list;	
	return &layer_console;
}

/*============================================================================*/
/* Local functions implementations.                                           */
/*============================================================================*/

void console_get_command_list(command_t **command_arg, int *size) {
	*command_arg = commands;
	*size = sizeof(commands);
}
/******************************************************************************/
void console_execute_command(char *out_buffer, int buffer_len, 
		int function_id, char *args) {
	switch (function_id) {
		case COMMAND_SESSIONS:
			console_print_sessions(out_buffer, buffer_len, args);
			break;
		case COMMAND_STATISTICS:
			console_print_statistics(out_buffer, buffer_len, args);
			break;
		case COMMAND_ALGORITHMS:
			console_print_algorithms(out_buffer, buffer_len, args);
			break;
		case COMMAND_DH_PARAMS:
			console_print_dh_params(out_buffer, buffer_len, args);
			break;
		case COMMAND_KEYS:
			console_print_keys(out_buffer, buffer_len, args);
			break;
		case COMMAND_CONNECT:
			console_connect(out_buffer, buffer_len, args);
			break;
		case COMMAND_DISCONNECT:
			console_disconnect(out_buffer, buffer_len, args);
			break;
		case COMMAND_CLOSE:
			console_close_session(out_buffer, buffer_len, args);
			break;
		case COMMAND_WRITE:
			console_write_data(out_buffer, buffer_len, args);
			break;
		case COMMAND_READ:
			console_read_data(out_buffer, buffer_len, args);
			break;
		case COMMAND_FLUSH:
			console_flush(out_buffer, buffer_len, args);
			break;
	}
}
/******************************************************************************/
void console_print_sessions(char *out_buffer, int buffer_len, char *args) {
	int i;
	struct in_addr ip;
	
	out_buffer[0] = '\0';
	console_printf(out_buffer, buffer_len, 
			"%-10s %-10s %21s %20s  %-10s %-10s\n", 
			"Local #",
			"Foreign #",
			"Foreign Address",
			"State",
			"Timeout",
			"Silent");
	for (i = 0; i < LLP_MAX_SESSIONS; i++) {

		llp_lock_session(i);

		if (llp_sessions[i].state != LLP_STATE_CLOSED) {
			ip = llp_sessions[i].address.sin_addr;
			console_printf(out_buffer, buffer_len, 
					"%-10d %-10d %15s:%-5d %20s  %-10d %-10d\n", 
					i, 
					llp_sessions[i].foreign_session,
					inet_ntoa(ip),
					ntohs(llp_sessions[i].address.sin_port),
					llp_states[llp_sessions[i].state],
					(llp_sessions[i].timeout*LLP_TIME_TICK)/1000,
					(llp_sessions[i].silence*LLP_TIME_TICK)/1000);
		}
		
		llp_unlock_session(i);
	}
}
/******************************************************************************/
void console_print_statistics(char *out_buffer, int buffer_len, char *args) {
	int i;
	struct in_addr ip;
	
	out_buffer[0] = '\0';
	console_printf(out_buffer, buffer_len, "%-10s %-10s %-10s %-10s\n", 
			"Local #",
			"Foreign #",
			"Sent",
			"Recv");
	for (i = 0; i < LLP_MAX_SESSIONS; i++) {

		llp_lock_session(i);

		if (llp_sessions[i].state == LLP_STATE_ESTABLISHED) {
			ip = llp_sessions[i].address.sin_addr;
			console_printf(out_buffer, buffer_len, 
					"%-10d %-10d %-10d %-10d\n", 
					i,
					llp_sessions[i].foreign_session,
					llp_sessions[i].packets_sent,
					llp_sessions[i].packets_received);
		}
		
		llp_unlock_session(i);
	}
}
/******************************************************************************/
void console_print_algorithms(char *out_buffer, int buffer_len, char *args) {
	int i;
	struct in_addr ip;
	console_printf(out_buffer, buffer_len, "%-8s %-10s %s\n", 
			"Local #",
			"Foreign #",
			"cipher(block size):hash:mac(length)");
			
	for (i = 0; i < LLP_MAX_SESSIONS; i++) {
		
		llp_lock_session(i);
		
		if (llp_sessions[i].state == LLP_STATE_ESTABLISHED) {
			ip = llp_sessions[i].address.sin_addr;
			console_printf(out_buffer, buffer_len, 
					"%-8d %-10d   %s(%d):%s:%s(%d)\n", 
					i, 
					llp_sessions[i].foreign_session,
					llp_sessions[i].cipher->name,
					llp_sessions[i].cipher->block_size,
					llp_sessions[i].hash->name,
					llp_sessions[i].mac->name,
					llp_sessions[i].mac->length);
		}
		
		llp_unlock_session(i);
	}
}
/******************************************************************************/
void console_print_dh_params(char *out_buffer, int buffer_len, char *args) {
	int session;
	char *tok;
	char *endptr;
	
	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	session = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}

	llp_lock_session(session);
	
	if (llp_sessions[session].state == LLP_STATE_ESTABLISHED) {
		console_printf(out_buffer, buffer_len, "   y_in:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].y_in, 
				MPINT_LENGTH(llp_sessions[session].y_in) + MPINT_SIZE_LENGTH);
				
		console_printf(out_buffer, buffer_len, "   y_out:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].y_out, 
				MPINT_LENGTH(llp_sessions[session].y_out) + MPINT_SIZE_LENGTH);
				
		console_printf(out_buffer, buffer_len, "   z:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].z, 
				MPINT_LENGTH(llp_sessions[session].z) + MPINT_SIZE_LENGTH);
				
		console_printf(out_buffer, buffer_len, "   h_in:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].h_in, 
				LLP_H_LENGTH);
				
		console_printf(out_buffer, buffer_len, "   h_out:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].h_out, 
				LLP_H_LENGTH);
				
		console_printf(out_buffer, buffer_len, "   close_verifier:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].verifier, 
				llp_sessions[session].hash->length);
	} else {
		console_printf(out_buffer, buffer_len, "session not established yet\n");
	}
	
	llp_unlock_session(session);
}
/******************************************************************************/
void console_print_keys(char *out_buffer, int buffer_len, char *args) {
	int session;
	char *tok;
	char *endptr;
	
	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	session = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}
	
	llp_lock_session(session);

	if (llp_sessions[session].state == LLP_STATE_ESTABLISHED) {
		console_printf(out_buffer, buffer_len, "   cipher_in_key:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].cipher_in_key,
				llp_sessions[session].cipher->key_length);

		console_printf(out_buffer, buffer_len, "   cipher_out_key:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].cipher_out_key,
				llp_sessions[session].cipher->key_length);

		console_printf(out_buffer, buffer_len, "   cipher_in_iv:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].cipher_in_iv,
				llp_sessions[session].cipher->iv_length);

		console_printf(out_buffer, buffer_len, "   cipher_out_iv:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].cipher_out_iv,
				llp_sessions[session].cipher->iv_length);

		console_printf(out_buffer, buffer_len, "   mac_in_key:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].mac_in_key, 
				llp_sessions[session].mac->key_length);

		console_printf(out_buffer, buffer_len, "   mac_out_key:");
		console_dump(out_buffer, buffer_len, 
				llp_sessions[session].mac_out_key, 
				llp_sessions[session].mac->key_length);
	} else {
		console_printf(out_buffer, buffer_len, "session not established yet\n");
	}
	
	llp_unlock_session(session);
}
/******************************************************************************/
void console_connect(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	struct sockaddr_in address;
	char *endptr;
	char *hostname;
	int port;

	tok = strtok(args, ": \n");
	if (tok == NULL) {
		return;
	}

	hostname = tok;	
	
	tok = strtok(NULL, " \n");
	if (tok == NULL) {
		return;
	}

	port = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}
	
	if (resolve_name(&address, hostname, port) == LLP_ERROR) {
		console_printf(out_buffer, buffer_len, 
				"Error cannor resolve hostname: %s.\n", hostname);
		return;
	}
	
	if (llp_connect_to(&address) != LINK_ERROR) {
		console_printf(out_buffer, buffer_len, "Connection request sent.\n");
	} else {
		console_printf(out_buffer, buffer_len, "Error connecting.\n");
	}
}
/******************************************************************************/
void console_disconnect(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	char *endptr;
	int session;


	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	session = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}
	
	if (llp_disconnect(session) != LINK_ERROR) {
		console_printf(out_buffer, buffer_len, "Close request sent.\n");
	} else {
		console_printf(out_buffer, buffer_len, "Error disconnecting.\n");
	}	
}
/******************************************************************************/
void console_close_session(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	char *endptr;
	int session;


	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	session = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}
	
	llp_close_session(session);
	console_printf(out_buffer, buffer_len, "Session closed.\n");
}
/******************************************************************************/
void console_write_data(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	char *endptr;
	int session;


	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	session = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}

	tok = strtok(NULL, " \n");
	if (tok == NULL) {
		return;
	}
	
	llp_write(session, (u_char *)tok, strlen(tok)+1);
	console_printf(out_buffer, buffer_len, "Message sent.\n");
}
/******************************************************************************/
void console_read_data(char *out_buffer, int buffer_len, char *args) {
	int session;
	int return_value;
	u_char buffer[1000]; // TODO, colocar constante FTU

	return_value = llp_read(&session, buffer, sizeof(buffer));
	if (return_value == LINK_ERROR) {
		console_printf(out_buffer, buffer_len, "Error reading.\n");
	} else {
		console_printf(out_buffer, buffer_len, 
				"Message read from session %d.\n", session);
		console_dump(out_buffer, buffer_len, buffer, return_value);
	}
}
/******************************************************************************/
void console_flush(char *out_buffer, int buffer_len, char *args) {
	int return_value;
	
	return_value = llp_flush();
	console_printf(out_buffer, buffer_len, 
			"Messages flushed: %d.\n", return_value);
}
/******************************************************************************/
int resolve_name(struct sockaddr_in *address, char *hostname, int port) {
	struct addrinfo *result;
	struct addrinfo hints;
	int error;

	/* Only IPv4 addresses supported. */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_INET;

	error = getaddrinfo(hostname, NULL, &hints, &result);
	if (error) {
		return LLP_ERROR;
	} else {
		if (result->ai_addrlen == sizeof(struct sockaddr_in)) {
			memcpy(address, result->ai_addr, sizeof(struct sockaddr_in));
			address->sin_port =	htons(port);
		}
		freeaddrinfo(result);
		return LLP_OK;
	}
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
