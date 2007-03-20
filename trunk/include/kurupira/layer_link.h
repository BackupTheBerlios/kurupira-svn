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
 * @file layer_link.h
 * 
 * Interface that a link layer module must implement.
 * 
 * @version $Header$
 * @ingroup kurupira
 */

#ifndef _LAYER_LINK_H_
	#define _LAYER_LINK_H_

	#include <sys/types.h>
	#include <netinet/in.h>

	/**
	 * Used to inform that a function ended properly.
	 */
	#define LINK_OK		1
	/**
	 * Used to inform that a function ended with an error.
	 */
	#define LINK_ERROR	0

	/**
	 * Data type used to exchange nodes lists.
	 */
	typedef struct {
		struct in_addr *address; /**< Peer's address. */
		int port; /**< Listening port to connect to. */
	} link_node_t;

	/**
	 * Structure representing the interface to the link layer
	 */
	typedef struct {
		/**
		 * Pointer to link layer initialization function.
		 * 
		 * @param[in] config    - the path to configuration file
		 */
		int (*link_init) (char *config);

		/**
		 * Pointer to link layer finalization function.
		 */
		void (*link_finish) ();
		/**
		 * Pointer to a function that establishes a connection to a node.
		 * 
		 * @param address		- address to connect to.
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_connect_to) (struct sockaddr_in * address);
		/**
		 * Pointer to a function that establishes a new connection, to a node
		 * present in the nodes pool.
		 * 
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_connect_any) ();
		/** 
		 * Pointer to a function that registers a callback that will be called each
		 * time a new connection is established.
		 * 
		 * @param connect_handler - the session number of the new connection.
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_register_connect) (void (*connect_handler) (int session));
		/**
		 * Pointer to a function that unregisters a function that was previously
		 * registered to handle new connection events.
		 * 
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_unregister_connect) ();
		/**
		 * Pointer to a function that registers a callback that will be called each
		 * time a session is closed.
		 * 
		 * @param close_handler - the number of the session being closed.
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_register_close) (void (*close_handler) (int session));
		/** 
		 * Pointer to a function that unregisters a callback that was previosuly
		 * registered to be called when a session was closed.
		 * 
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_unregister_close) ();
		/**
		 * Pointer to a function that reads datagrams received by the link layer.
		 * 
		 * @param session - the session that the datagram was received.
		 * @param data - the buffer to store the data being read.
		 * @param max - the buffer capacity.
		 * @return number of bytes stored in data, LINK_ERROR if errors occurred.
		 */
		int (*link_read) (int *session, u_char * data, int max);
		/**
		 * Pointer to a function that writes data to a session established by the
		 * link layer.
		 * 
		 * @param session - the session number to write to.
		 * @param data - the data to write.
		 * @param length - data length in bytes.
		 * @return LINK_OK if no errors occurred, LINK_ERROR if errors occurred.
		 */
		int (*link_write) (int session, u_char * data, int length);
		/**
		 * Pointer to a function that disconnects a session.
		 * 
		 * @param session - the session to disconnect.
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_disconnect) (int session);
		/**
		 * Pointer to a function that returns the last error occurred in a session.
		 * 
		 * @param session - the session number.
		 * @return LINK_OK if no errors occurred, LINK_ERROR otherwise.
		 */
		int (*link_get_last_error) (int session);
	} layer_link_t;

	/**
	 * Returns the layer_link_t struct with function pointers of the link layer.
	 * 
	 * @return pointer to the layer_link_t struct.
	 */
	layer_link_t *link_get_interface();

	/** 
	 * Initializes the link layer.
	 * 
	 * @param config_name - the configuration file. If NULL is passed, the link
	 *      layer must provide default configuration or use default configuration
	 *      file.
	 * @return LINK_OK if successful, or LINK_ERROR on error condition.
	 */
	int link_initialize(char *config_name);

	/**
	 * Finalizes the link layer.
	 */
	void link_finalize();

#endif /* !_LAYER_LINK_H_ */
