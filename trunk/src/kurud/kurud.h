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
 * @defgroup kurud kurud, the Kurupira daemon
 */

/**
 * @file kurud.h
 * 
 * Global values and daemon interface.
 * 
 * @version $Header$
 * @ingroup kurud
 */

#ifndef _KURUD_H_
	#define _KURUD_H_

	#include <kurupira/layer_console.h>
	#include <kurupira/layers.h>

	/**
	 * Constant indicating success.
	 */
	#define KURUD_OK		1

	/**
	 * Constant indicating error.
	 */
	#define KURUD_ERROR	0

	/**
	 * Contains the addresses of the link layer functions.
	 */
	extern layer_link_t *kurud_link_layer;

	/**
	 * Contains the addresses of the net layer functions.
	 */
	extern layer_net_t *kurud_net_layer;

	/**
	 * Contains the addresses of the link layer console functions.
	 */
	extern layer_console_t *kurud_link_console;

	/**
	 * Contains the addresses of the net layer console functions.
	 */
	extern layer_console_t *kurud_net_console;

	/**
	 * Contains the addresses of the reliable layer console functions.
	 */
	extern layer_console_t *kurud_reliable_console;

	/**
	 * Contains the addresses of the unreliable layer console functions.
	 */
	extern layer_console_t *freedomd_unreliable_console;

	/**
	 * Loads and configure all the modules. If an invalid configuration file
	 * is passed as argument, the default configuration file is used.
	 * 
	 * @param[in] config 	- the configuration file
	 * @return KURUD_OK if no errors occurred, KURUD_ERROR otherwise.
	 */
	int kurud_init(char *config);

	/**
	 * Unload all the modules initialized.
	 * 
	 * @return KURUD_OK if no errors occurred, KURUD_ERROR otherwise.
	 */
	int kurud_finish();

	/**
	 * Wait for the finalization of the daemon.
	 * 
	 * @return KURUD_OK if no errors occurred, KURUD_ERROR otherwise.
	 */
	int kurud_wait();

#endif /* !_KURUD_H_ */
