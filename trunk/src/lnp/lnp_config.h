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
 * @file lnp_config.h Config routines for the LNP module.
 * @ingroup lnp
 */
 
#ifndef _LNP_CONFIG_H_
#define _LNP_CONFIG_H_
 
#include <util/util_crypto.h>

/**
 * Reads the configuration file looking for configuration parameter definitions.
 * 
 * @param config_name name of the configuration file.
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_configure(char *config_name);

/**
 * Restores the default configuration parameters.
 */
void lnp_unconfigure();

/**
 * Returns the first algorithm available from the list of ciphers. If the 
 * algorithm is not available, NULL is returned.
 * 
 * @param cipher_list list of function names, separated with semicolons or a
 * 		single function name.
 * @return pointer to function that inmplements the algorithm.
 */
util_cipher_function_t *lnp_cipher_search(char *cipher_list);

/**
 * Returns the first algorithm available from the list of hash functions. If the
 * algorithm is not available, NULL is returned.
 * 
 * @param hash_list list of function names, separated with semicolons or a
 * 		single function name.
 * @return pointer to function that inmplements the algorithm.
 */
util_hash_function_t *lnp_hash_search(char *hash_list);

/**
 * Returns the first algorithm available from the list of MAC functions. If the
 * algorithm is not available, NULL is returned.
 * 
 * @param mac_list list of function names, separated with semicolons or a
 * 		single function name.
 * @return pointer to function that implements the algorithm.
 */
util_mac_function_t *lnp_mac_search(char *mac_list);

/**
 * Returns the key stores capacity (in connections).
 * 
 * @returns current key store capacity.
 */
int lnp_get_key_store_size();
 
/**
 * Returns the name of the file that contains the node's public key.
 * 
 * @return name of file containing the public key.
 */
char *lnp_get_public_key_file();

/**
 * Returns the name of the file that contains the node's private key.
 * 
 * @return name of file containing the private key.
 */
char *lnp_get_private_key_file();

/**
 * Fills a string containing all cipher functions supported. The string must be
 * pre-allocated, and the parameter max controls the maximum number of bytes
 * that can be written in string, including the terminating \\0. If the string
 * capacity is not enough to store the amount of data needed, an error is
 * returned.
 * 
 * @param string array that will store the ciphers string.
 * @param max maximum number of bytes that can be written in string.
 * @return the number of bytes written in string, LNP_ERROR otherwise.
 */
int lnp_get_cipher_string(char *string, int max);

/**
 * Fills a string containing all hash functions supported. The string must be
 * pre-allocated, and the parameter max controls the maximum number of bytes
 * that can be written in string, including the terminating \\0. If the string
 * capacity is not enough to store the amount of data needed, an error is
 * returned.
 * 
 * @param string array that will store the hash string.
 * @param max maximum number of bytes that can be written in string.
 * @return the number of bytes written in string, LNP_ERROR otherwise.
 */
int lnp_get_hash_string(char *string, int max);

/**
 * Fills a string containing all MAC functions supported. The string must be
 * pre-allocated, and the parameter max controls the maximum number of bytes
 * that can be written in string, including the terminating \\0. If the string
 * capacity is not enough to store the amount of data needed, an error is
 * returned.
 * 
 * @param string array that will store the MAC string.
 * @param max maximum number of bytes that can be written in string.
 * @return the number of bytes written in string, LNP_ERROR otherwise.
 */
int lnp_get_mac_string(char *string, int max);

#endif /* !_LNP_CONFIG_H_ */
