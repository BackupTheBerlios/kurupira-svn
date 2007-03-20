/*
 * Copyright (C) 2006-07 The Kurupira Project
 * 
 * Kurupira is the legal property of its developers, whose names are not listed
 * here. Please refer to the COPYRIGHT file.
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
 * @defgroup libconsole libconsole
 */

/**
 * @file libconsole.h
 * 
 * Interface to the static library used to communicate with daemon console.
 * Include this file if you wish to communicate to freedomd console module.
 * 
 * @version $Header$
 * @ingroup libconsole
 */

#ifndef _LIBCONSOLE_H_
	#define _LIBCONSOLE_H_

	#include <libfreedom/layer_console.h>

	/**
	 * Constant indicating success
	 */
	#define LIBCONSOLE_OK		1

	/**
	 * Constant indicating error in connection
	 */
	#define LIBCONSOLE_ERROR	0

	/**
	 * Constant indicating that the command execution was sent, but
	 * its arguments were wrong.
	 */
	#define LIBCONSOLE_COMMAND_ERROR	-1

	/**
	 * Data type that stores a list of commands.
	 */
	typedef struct {
		command_t *list; /**< List of command_t structs. */
		int size; /**< Number of elements in the list. */
	} command_list_t;

	/**
	 * Loads a list of commands from a layer.
	 * 
	 * @param commands	- the list of commands
	 * @param layer 	- the layer
	 * @return LIBCONSOLE_OK if no error occurs, LIBCONSOLE_ERROR otherwise.
	 */
	int libconsole_load_commands(command_list_t * commands, int layer);

	/**
	 * Requests a command to the a given layer loaded by the daemon.
	 * 
	 * @param layer 	- the layer
	 * @param command 	- the identifier of the command
	 * @param args 		- a null terminated string with the command arguments
	 * @return LIBCONSOLE_OK if no error occurs, LIBCONSOLE_ERROR otherwise.
	 */
	int libconsole_send_command(int layer, int command, char *args);

#endif /* !_LIBCONSOLE_H_ */
