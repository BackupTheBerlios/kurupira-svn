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
 * @file layer_net.h
 * 
 * Interface that a network Layer module must implement.
 * 
 * @version $Header$
 * @ingroup kurupira
 */

#ifndef _LAYER_NET_H_
	#define _LAYER_NET_H_

	#include <sys/types.h>
	#include <netinet/in.h>

	#include <kurupira/layer_link.h>

	/**
	 * Used to inform that a function ended properly.
	 */
	#define NET_OK		1
	/**
	 * Used to inform that a function ended with an error.
	 */
	#define NET_ERROR	0

	/**
	 * Constant used to specify reliable transport protocol. This constant
	 * is the one used at LNP_DATA packets.
	 */
	#define PROTOCOL_RELIABLE 1
	/**
	 * Constant used to specify unreliable transport protocol. This constant
	 * is the one used at LNP_DATA packets.
	 */
	#define PROTOCOL_UNRELIABLE 2

	/**
	 * Length of the net id, in bytes.
	 */
	#define NET_ID_LENGTH 20

	/**
	 * Data type used to represent the net id.
	 */
	typedef u_char net_id_t[NET_ID_LENGTH];

	/**
	 * Structure representing the interface to the net layer.
	 */
	typedef struct {
		/**
		 * Pointer to network layer initialization function.
		 * 
		 * @param[in] config    - the path to configuration file
		 */
		int (*net_init) (char *config);
		/**
		 * Pointer to network layer finalization function.
		 */
		void (*net_finish) ();		
		/**
		 *  Pointer to a function that reads datagrams received by the net layer.
		 * 
		 * @param protocol - transport protocol being used.
		 * @param id - source address (ID) of this datagram.
		 * @param data - the buffer to store the data being read.
		 * @param max - the buffer capacity, in bytes.
		 * @return number of bytes read, NET_ERROR if errors occurred.
		 */
		int (*net_read) (u_char * protocol, net_id_t * id, u_char * data, int max);
		/**
		 * Pointer to a function that sends data by a connection established
		 * by the net layer.
		 * 
		 * @param protocol - transport protocol being used.
		 * @param id - target address (ID) of this datagram.
		 * @param data - the data to be written.
		 * @param length - size of data in bytes.
		 * @return NET_OK if no errors occurred, NET_ERROR otherwise.
		 * */
		int (*net_write) (u_char protocol, net_id_t * id, u_char * data,
			int length);
		//TODO Verificar se isto deve existir mesmo.
		int (*net_get_last_error) (int session);
	} layer_net_t;

	/**
	 * Returns the layer_net_t struct with function pointers of the net layer.
	 * 
	 * @return pointer to the layer_net_t struct.
	 */
	layer_net_t *net_get_interface();

	/** 
	 * Initializes the net layer.
	 * 
	 * @param config_name - the configuration file. If NULL is passed, the 
	 *      net layer must provide default configuration or use a default
	 *      configuration file.
	 * @param link_interface - pointers to loaded link layer module.
	 * @return NET_OK if successful, or NET_ERROR on error condition.
	 */
	int net_initialize(char *config_name, layer_link_t * link_interface);

	/**
	 * Finalizes the net layer.
	 */
	void net_finalize();

#endif /* !_LAYER_NET_H_ */
