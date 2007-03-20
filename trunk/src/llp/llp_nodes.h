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
 * @file llp_nodes.h Headers of routines used to manipulate tables of active
 * 		connected hosts and nodes cache.
 * @ingroup llp
 */

#ifndef _LLP_HOSTS_H_
#define _LLP_HOSTS_H_

#include <netinet/in.h>

/**
 * Initializes the module, allocating needed memory and clearing data
 * structures.
 * 
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_nodes_initialize();

/**
 * Frees the memory allocated to this module.
 */
void llp_nodes_finalize();

/**
 * Returns the session identifier used to connect to the node specified in
 * in address, or LLP_ERROR if there's no connection to this node.
 * 
 * @param address node address and port.
 * @return session identifier if a session is found, LLP_ERROR otherwise.
 */
int llp_get_session_by_address(struct sockaddr_in *address);

/**
 * Copies the addresses of n nodes on cache to the array. If there's no nodes on
 * cache, LLP_ERROR is returned. The array must be pre-allocated with enough 
 * capacity to store all addresses.
 * 
 * @param number number of addresses requested.
 * @param addresses array that will receive the node address.
 * @return number of nodes found, LLP_ERROR if errors occurred.
 */
int llp_get_nodes_from_cache(int number, struct sockaddr_in *addresses);

/**
 * Adds a node to the node pool. If there's no room to store this node, it will
 * substitute the first inactive node found. If the node is already there,
 * LLP_ERROR is returned.
 * 
 * @param address node address and port.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_add_node_to_cache(struct sockaddr_in *address);

/**
 * Updates a node present in cache to be considered active. 
 * 
 * @param address node address and port.
 * @param session session identifier that will be associated o this node.
 * @return LLP_OK if no errors occures, LLP_ERROR otherwise.
 */
int llp_set_node_active(struct sockaddr_in *address, int session);

/**
 * Updates a node present in cache to be considered inactive. 
 * 
 * @param session session currently associated with the node.
 * @return LLP_OK ir no errors occurred, LLP_ERROR otherwise.
 */
int llp_set_node_inactive(int session);

/**
 * Updates a node present in cache to be considered in handshake process. 
 * 
 * @param address node address.
 * @param session session currently associated with the node.
 * @return LLP_OK ir no errors occurred, LLP_ERROR otherwise.
 */
int llp_set_node_connecting(struct sockaddr_in *address, int session);

/**
 * Copies the address of an inactive node on cache to address. If there's no
 * inactive node on cache, LLP_ERROR is returned.
 * 
 * @param address address that will receive the node address.
 * @return LLP_OK if there was a inactive onde on cache, LLP_ERROR otherwise.
 */
int llp_get_inactive_node(struct sockaddr_in *address);

/**
 * Monitor the percent of the cache that is filled, and sends LLP_NODE_HUUNT
 * packets if needed.
 */
void llp_handle_nodes();

#endif /* !_LLP_HOSTS_H_ */
