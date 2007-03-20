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
 * @file layer_console.h
 * 
 * Interface that a layer must implement to support console interactivity.
 * 
 * @version $Header$
 * @ingroup kurupira
 */

#ifndef _LAYER_CONSOLE_H_
	#define _LAYER_CONSOLE_H_

	/**
	 * Constant indicating success.
	 */
	#define CONSOLE_OK		1
	/**
	 * Constant indicating error.
	 */
	#define CONSOLE_ERROR	0

	/**
	 * Maximum length of a command name.
	 */
	#define COMMAND_NAME_LENGTH		32

	/**
	 * Maximum length of a command documentation.
	 */
	#define COMMAND_DOC_LENGTH		64

	/**
	 * A structure which contains information on the possible executable 
	 * commands. This allows the mapping of command names to command ids, which 
	 * make the command execution switch extremely simple. Negative command 
	 * identifiers are reserved and should no be used.
	 */
	typedef struct {
		/** Command identifier. */
		int id;
		/** User printable name of the function. */
		char name[COMMAND_NAME_LENGTH];
		/**< Documentation for this function.  */
		char doc[COMMAND_DOC_LENGTH];
	} command_console_t;

	/**
	 * Data type that stores a list of commands.
	 */
	typedef struct {
		command_console_t *list; /**< List of commands. */
		int size; /**< Number of elements in the list. */
	} command_list_t;

	/**
	 * Structure representing the interface to a console.
	 */
	typedef struct {
		/**
		 * Pointer to a function that executes the command whose id is given.
		 * If an error occurs during the command execution, the function must
		 * return CONSOLE_ERROR. 
		 * 
		 * @param[out] out      - the output buffer 
		 * @param[in] out_len   - the size of the output buffer
		 * @param[in] command   - the command identifier
		 * @param[in] args      - the command arguments
		 * @return CONSOLE_OK if no error occurs, CONSOLE_ERROR otherwise.
		 */
		int (*console_execute) (char *output, int out_len, int command, char *args);
		/**
		 * Pointer to a function that returns a reference to a list of commands.
		 * 
		 * @param[out] commands - the list of commands returned
		 * @return CONSOLE_OK if no error occurs, CONSOLE_ERROR otherwise.
		 */
		int (*console_get_commands) (command_console_t **list, int *size);
	} layer_console_t;

	/**
	 * Returns the interface to the console layer.
	 * 
	 * @param[out] interface        - the interface returned
	 * @return CONSOLE_OK if no error occurs, CONSOLE_ERROR otherwise.
	 */
	int console_get_interface(layer_console_t ** interface);

#endif /* !_LAYER_CONSOLE_H_ */
