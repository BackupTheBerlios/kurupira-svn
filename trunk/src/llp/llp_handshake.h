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
 * @file llp_handshake.h Functions used to establish a new connection.
 * @ingroup llp
 */
 
#ifndef _LLP_HANDSHAKE_H_
#define _LLP_HANDSHAKE_H_

#include <sys/types.h>
#include <netinet/in.h>

/**
 * Handles the event of receiving a LLP_CONNECTION_REQUEST packet.
 * 
 * @param packet_data - packet data.
 * @param packet_length - packet length in bytes;
 * @param peer - peer trying to connect.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_handle_connection_request(u_char *packet_data, int packet_length,
		struct sockaddr_in *peer);
		
/**
 * Handles the event of receiving a LLP_CONNECTION_OK packet.
 * 
 * @param packet_data - packet data.
 * @param packet_length - packet length in bytes;
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_handle_connection_ok(u_char *packet_data, int packet_length);

/**
 * Handles the event of receiving a LLP_KEY_EXCHANGE packet.
 * 
 * @param packet_data - packet data.
 * @param packet_length - packet length in bytes;
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_handle_key_exchange(u_char *packet_data, int packet_length);

/**
 * Connects to the given host and tries to insert it on cache.
 * 
 * @param address - node address.
 * @return LLP_OK if no erros occurred, LINK_ERROR otherwise.
 */
int llp_connect_to(struct sockaddr_in *address);

/**
 * Connects to a handle node present on cache.
 * 
 * @return LLP_OK if no errors occurred, LINK_ERROR otherwise.
 */
int llp_connect_any();

/**
 * Registers a function to be called each time a new connection is established.
 * 
 * @param handler - function to be called.
 * @return LLP_OK if no errors occurred, LINK_ERROR otherwise.
 */
int llp_register_connect(void (*handler)(int session));

/**
 * Unregister a previously registered function to treat new connection events.
 * 
 * @return LLP_OK if no errors occurred, LINK_ERROR otherwise.
 */
int llp_unregister_connect();
	
#endif /* !_LLP_HANDSHAKE_H_ */
