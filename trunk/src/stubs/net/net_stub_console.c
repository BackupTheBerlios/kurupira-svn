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
 * @file net_stub_console.c Console interface stub for net module.
 * @ingroup net_stub
 */

#include <string.h> 
#include <stdio.h> 
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>

#include <libfreedom/layer_link.h>
#include <libfreedom/layer_console.h>

#include "net_stub.h"

/*============================================================================*/
/* Local functions prototypes.                                                */
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
 * My implementation for console_execute_command.
 */
static void my_console_execute_command(char *out_buffer, int buffer_len, 
		int function_id, char *args);
		
/*
 * My implementation for console_get_command_list.
 */
static void my_console_get_command_list(command_t **command_arg, int *size);

/*
 * Execute COMMAND_WRITE_BENCHMARK command.
 */
static void console_write_benchmark(char *out_buffer, 
		int buffer_len, char *args);

/*
 * Execute COMMAND_READ_BENCHMARK command.
 */
static void console_read_benchmark(char *out_buffer, 
		int buffer_len, char *args);

/*============================================================================*/
/* Local data definitions.                                                    */
/*============================================================================*/

/*
 * console interface struct.
 */
static layer_console_t layer_console = {
	my_console_execute_command,
	my_console_get_command_list
};

/*
 * Command identifiers.
 */
#define COMMAND_WRITE_BENCHMARK		1
#define COMMAND_READ_BENCHMARK		2

/*
 * All available commands to link stub module.
 */
static command_t commands[] = {
	{COMMAND_WRITE_BENCHMARK, "write_benchmark", 
			"[write_benchmark <session> <count>]"
			" - write <count> packets at session <session>."},
	{COMMAND_READ_BENCHMARK, "read_benchmark", 
			"[read_benchmark <count>]"
			" - read <count> packets from link layer."},
};

/*============================================================================*/
/* Exported functions implementations.                                        */
/*============================================================================*/

layer_console_t *get_console_interface() {
	return &layer_console;
}
/******************************************************************************/
static void my_console_execute_command(char *out_buffer, int buffer_len, 
		int function_id, char *args) {
	switch (function_id) {
		case COMMAND_WRITE_BENCHMARK:
			console_write_benchmark(out_buffer, buffer_len, args);
			break;
		case COMMAND_READ_BENCHMARK:
			console_read_benchmark(out_buffer, buffer_len, args);
			break;
	}
}
/******************************************************************************/
static void my_console_get_command_list(command_t **command_arg, int *size) {
	*command_arg = commands;
	*size = sizeof(commands);	
}

/*============================================================================*/
/* Local functions implementations.                                           */
/*============================================================================*/

void console_write_benchmark(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	char *endptr;
	int session;
	int count;
	int i;
	struct timeval time;
	struct timezone timezone;
	struct timeval start_time;
	double diff_time;

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
	
	count = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}

	layer_link->link_write(session, (u_char *)&i, sizeof(i));
	gettimeofday(&start_time, &timezone);
	for (i = 0; i < count; i++) {
		layer_link->link_write(session, (u_char *)&i, sizeof(i));
		/*console_printf(out_buffer, buffer_len, "message sent.\n");*/
	}
	gettimeofday(&time, &timezone);
	diff_time = (time.tv_sec - start_time.tv_sec) + 
			(time.tv_usec - start_time.tv_usec)/1000000.0;
	console_printf(out_buffer, buffer_len, "%d messages sent.\n", count);
	console_printf(out_buffer, buffer_len, "in %.03lf seconds.\n", diff_time);
}
/******************************************************************************/
void console_read_benchmark(char *out_buffer, int buffer_len, char *args) {
	char *tok;
	char *endptr;
	int session;
	int return_value;
	int i;
	int count;
	u_char buffer[1000]; // TODO, colocar constante FTU
	struct timeval time;
	struct timezone timezone;
	struct timeval start_time;
	double diff_time;

	tok = strtok(args, " \n");
	if (tok == NULL) {
		return;
	}

	count = strtol(tok, &endptr, 10);
	if (*tok=='\0' || *endptr!='\0') {
		return;
	}

	return_value = layer_link->link_read(&session, buffer, sizeof(buffer));
	gettimeofday(&start_time, &timezone);
	int last_id = -1;
	int current_id = 0;
	for (i = 0; i < count; i++) {
		return_value = layer_link->link_read(&session, buffer, sizeof(buffer));
		if (return_value == LINK_ERROR) {
			console_printf(out_buffer, buffer_len, "Error reading.\n");
		} else {
			current_id = *(int*)buffer;
			if (current_id != last_id+1) {
				console_printf(out_buffer, buffer_len, 
						"Mising packet. Last: %d. Current: %d\n", 
						last_id, current_id);
			}
			last_id = current_id;
		}
	}
	gettimeofday(&time, &timezone);
	diff_time = (time.tv_sec - start_time.tv_sec) + 
			(time.tv_usec - start_time.tv_usec)/1000000.0;
	console_printf(out_buffer, buffer_len, "%d messages read.\n", count);
	console_printf(out_buffer, buffer_len, "in %.03lf seconds.\n", diff_time);
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
