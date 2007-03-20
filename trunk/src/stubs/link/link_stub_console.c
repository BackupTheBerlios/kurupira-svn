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
 * @file link_stub_console.c Console interface stub for link module.
 * @ingroup link_stub
 */

#include <string.h> 
#include <stdio.h> 
#include <stdarg.h>

#include <libfreedom/layer_console.h>

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
		int command_id, char *args);
		
/*
 * My implementation for console_get_command_list.
 */
static void my_console_get_command_list(command_t **command_arg, int *size);

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
 * All available commands to link stub module.
 */
static command_t commands[] = {
	{1, "command1", "[command1] - execute command 1"},
	{2, "command2", "[command2] - execute command 2"},
	{3, "command3", "[command3] - execute command 3"},
	{4, "command4", "[command4] - execute command 4"},
};

/*============================================================================*/
/* Exported functions implementations.                                        */
/*============================================================================*/

layer_console_t *get_console_interface() {
	return &layer_console;
}
/******************************************************************************/
static void my_console_execute_command(char *out_buffer, int buffer_len, 
		int command_id, char *args) {
	console_printf(out_buffer, buffer_len, 
			"command %d executed.\n", command_id);
	console_printf(out_buffer, buffer_len, 
			"  arguments: %s.\n", args);
}
/******************************************************************************/
static void my_console_get_command_list(command_t **command_arg, int *size) {
	*command_arg = commands;
	*size = sizeof(commands);	
}

/*============================================================================*/
/* Local functions implementations.                                           */
/*============================================================================*/

void console_printf(char *out, int buffer_len, const char * format, ...) {

	char line[100];
    va_list ap;

    va_start(ap, format);
	vsnprintf(line, sizeof(line), format, ap);
    va_end(ap);
    
    strncat(out, line, buffer_len - strlen(out) - 1);
}
/******************************************************************************/
