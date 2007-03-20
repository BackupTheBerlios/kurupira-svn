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
 * @file kurud_console.h
 * 
 * Interface between the console and the daemon, that executes commands
 * requested by the libconsole library.
 * 
 * @version $Header$
 * @ingroup freedomd
 */

#ifndef _FREEDOMD_CONSOLE_H_
	#define _FREEDOMD_CONSOLE_H_

	/**
	 * Command ID used to request the list of commands from a layer.
	 */
	#define KURUD_COMMAND_LIST_REQUEST		(-1)

	/**
	 * Creates the socket for receiving console commands and listens to each
	 * command request, delegating command execution to each layer.
	 * 
	 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
	 */
	int kurud_console_init();

	/**
	 * Waits for the termination of the console thread.
	 */
	int kurud_console_wait();

	/**
	 * Terminates the console module, freeing all resources used.
	 */
	int kurud_console_finish();

#endif /* !_FREEDOMD_CONSOLE_H_ */
