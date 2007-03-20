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
 * 
 * $Id$
 */

/**
 * @file llp_data.h Headers of functions used to manipulate LLP_DATA packets.
 * @ingroup llp
 */
 
#ifndef _LLP_DATA_H_
#define _LLP_DATA_H_

#include <sys/types.h>

/**
 * Handle a received LLP_DATA packet.
 * 
 * @param[in] packet_data 		- packet data.
 * @param[out] packet_length 	- packet length in bytes.
 * @retval LLP_OK 				- if no errors occurred
 * @retval LLP_ERROR			- otherwise
 */
int llp_handle_data(u_char *packet_data, int packet_length);

/**
 * Keeps the given session alive, sending the an LLP_KEEP_ALIVE packet.
 * 
 * @param[in] session	- session identifier.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
int llp_keep_session_alive(int session);

/**
 * Requests new nodes to the given session.
 * 
 * @param[in] session 	- session identifier.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
int llp_hunt_for_nodes(int session);

/**
 * Disconnects the given session.
 * 
 * @param[in] session	- session identifier.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
int llp_disconnect(int session);

/**
 * Reads data received by the LLP module.
 * 
 * @param[out] session 	- session that received this datagram.
 * @param[out] data 	- array that will receive data.
 * @param[in] max 		- max number of bytes that can be read (i.e., the size of data).
 * @return number in bytes of read, LLP_ERROR if errors occurred.
 */
int llp_read(int *session, u_char *data, int max);

/**
 * Sends generic data by the given session.
 * 
 * @param[in] session 	- session identifier.
 * @param[in] data 		- data to be sent.
 * @param[in] length 	- length of data in bytes.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
int llp_write(int session, u_char *data, int length);

/**
 * Removes all enqueued messages.
 * 
 * @return the number of messages flushed.
 */
int llp_flush();

/*
 * Registers a function to treat session closing events.
 * 
 * @param[in] handler	- function pointer.
 * @retval LLP_ERROR 	- if another function is registered
 * @retval LLP_OK 		- otherwise.
 */
int llp_register_close(void (*handler)(int session));

/**
 * Unregisters the functions used to treat session closing events.
 * 
 * @retval LLP_ERROR 	- if no function is registered
 * @retval LLP_OK		- otherwise.
 */
int llp_unregister_close();

/**
 * Checks if the last hunt node sent is still valid.
 * 
 * @retval LLP_OK 		- if the node hunt has not expired
 * @retval LLP_ERROR	- otherwise.
 */
int llp_hunt_valid(int session);

#endif /* !_LLP_DATA_H_ */
