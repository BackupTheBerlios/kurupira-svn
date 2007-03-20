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
 * $Id: llp_config.h,v 1.21 2005/10/10 02:03:06 iamscared Exp $
 */

/**
 * @file llp_config.h Headers of configuration routines for the LLP module.
 * @ingroup llp
 */
 
#ifndef _LLP_CONFIG_H_
#define _LLP_CONFIG_H_
 
#include <util/util_crypto.h>

/**
 * Reads the configuration file looking for parameter definitions.
 * 
 * @param[in] file_name - name of the configuration file.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR 	- otherwise
 */
int llp_configure(char *file_name);

/**
 * Restores the default configuration parameters.
 */
void llp_unconfigure();

/**
 * Returns the first algorithm available locally matching the list of ciphers.
 * 
 * @param[in] ciphers	- list of function names, separated with semicolons
 * 		or a single function name
 * @retval NULL			- if no algorithms are available
 * @return a pointer to the function that implements the algorithm.
 */
util_cipher_function_t *llp_search_cipher(char *ciphers);

/**
 * Returns the first algorithm available locally matching the list of hash
 * functions.
 * 
 * @param[in] hashes	- list of function names, separated with semicolons or a
 * 		single function name
 * @retval NULL			- if no algorithms are available
 * @return a pointer to a function that implements the algorithm.
 */
util_hash_function_t *llp_search_hash(char *hashes);

/**
 * Returns the first algorithm available locally matching the list of MAC
 * functions.
 * 
 * @param[in] macs 		- list of function names, separated with semicolons or a
 * 		single function name
 * @retval NULL			- if no algorithms are available
 * @return a pointer to the function that implements the algorithm.
 */
util_mac_function_t *llp_search_mac(char *macs);

/**
 * Returns the current port.
 * 
 * @return the current port being used.
 */
int llp_get_port();

/**
 * Returns the current minimum number of connections established.
 * 
 * @return the current minimum number of connections.
 */
int llp_get_min_connections();

/**
 * Returns the current maximum number of connections established.
 * 
 * @return the current maximum number of connections.
 */
int llp_get_max_connections();

/**
 * Returns the nodes cache capacity (in nodes).
 * 
 * @returns the current cache capacity.
 */
int llp_get_cache_size();
 
/**
 * Returns the session expiration time (in seconds).
 * 
 * @return the current session expiration time.
 */
int llp_get_expiration_time();

/**
 * Returns the name of the file that contains addresses and ports of nodes to be
 * stored on cache and will be persistent between executions.
 * 
 * @return name of file containing static node information.
 */
char *llp_get_static_nodes_file();

/**
 * Returns the name of the file that this module will use to save the list of
 * known nodes (cache) between executions.
 * 
 * @return the name of file containing dynamic node information.
 */
char *llp_get_recent_nodes_file();

/**
 * Fills a string containing all cipher functions supported. The string must be
 * pre-allocated, and the parameter max controls the maximum number of bytes
 * that can be written in string, including the terminating \\0. If the string
 * capacity is not enough to store the amount of data needed, an error is
 * returned.
 * 
 * @param[out] string 	- array that will store the ciphers string
 * @param[in] max 		- maximum number of bytes that can be written in string
 * @retval LLP_ERROR	- if the string capacity is not enough
 * @returns the number of bytes written in string.
 */
int llp_get_cipher_string(char *string, int max);

/**
 * Fills a string containing all hash functions supported. The string must be
 * pre-allocated, and the parameter max controls the maximum number of bytes
 * that can be written in string, including the terminating \\0. If the string
 * capacity is not enough to store the amount of data needed, an error is
 * returned.
 * 
 * @param[in] string 	- array that will store the hash string
 * @param[in] max 		- maximum number of bytes that can be written in string
 * @retval LLP_ERROR	- if the string capacity is not enough
 * @return the number of bytes written in string.
 */
int llp_get_hash_string(char *string, int max);

/**
 * Fills a string containing all MAC functions supported. The string must be
 * pre-allocated, and the parameter max controls the maximum number of bytes
 * that can be written in string, including the terminating \\0. If the string
 * capacity is not enough to store the amount of data needed, an error is
 * returned.
 * 
 * @param[out] string 	- array that will store the MAC string.
 * @param[in] max 		- maximum number of bytes that can be written in string.
 * @retval LLP_ERROR	- if the string capacity is not enough
 * @return the number of bytes written in string.
 */
int llp_get_mac_string(char *string, int max);

#endif /* !_LLP_CONFIG_H_ */
