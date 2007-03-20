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
 * @file lnp_store.c
 * @ingroup lnp
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <pthread.h>

#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>
#include <util/util_crypto.h>

#include "lnp.h"
#include "lnp_store.h"

/*============================================================================*/
/* Public data definitions.                                                   */
/*============================================================================*/

lnp_key_entry_t lnp_key_store[KEY_TABLE_SIZE];

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 *
 */
static u_int first_free_slot = 0;

/*
 * 
 */
static pthread_mutex_t lnp_key_store_mutex;

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/	   

int lnp_key_store_initialize() {
	int i;
	
	if (pthread_mutex_init(&lnp_key_store_mutex, NULL)) {
		return LNP_ERROR;
	}

	pthread_mutex_lock(&lnp_key_store_mutex);
	for (i=0; i<KEY_TABLE_SIZE-1; i++) {
		lnp_key_store[i].next_free_slot = i+1;
		/*if (pthread_mutex_init(&lnp_key_store[i].handshake_mutex, NULL) ||
				pthread_cond_init(&lnp_key_store[i].handshake_condition, NULL)){
			pthread_mutex_unlock(&lnp_key_store_mutex);
			return LNP_ERROR;
		}*/
	}
	lnp_key_store[i].next_free_slot = NULL_SLOT;
	first_free_slot = 0;
	pthread_mutex_unlock(&lnp_key_store_mutex);
	
	return LNP_OK;
}
/******************************************************************************/
void lnp_key_store_finalize() {
	/*int i;
	
	for (i=0; i<KEY_TABLE_SIZE-1; i++) {
		pthread_mutex_destroy(&lnp_key_store[i].handshake_mutex);
		pthread_cond_destroy(&lnp_key_store[i].handshake_condition);
	}*/

	pthread_mutex_destroy(&lnp_key_store_mutex);	
}
/******************************************************************************/
int lnp_key_store_new() {
	int result;

	pthread_mutex_lock(&lnp_key_store_mutex);
	result = first_free_slot;
	if (result == NULL_SLOT) {
		result = NULL_SLOT;	
	} else {
		first_free_slot = lnp_key_store[result].next_free_slot;
		lnp_key_store[result].next_free_slot = USED_SLOT;
	}
	pthread_mutex_unlock(&lnp_key_store_mutex);
	
	return result;
}
/******************************************************************************/
void lnp_key_store_delete(int key_entry_index) {
	pthread_mutex_lock(&lnp_key_store_mutex);
	if (lnp_key_store[key_entry_index].next_free_slot == USED_SLOT) {
		lnp_key_store[key_entry_index].next_free_slot = first_free_slot;
		first_free_slot = key_entry_index;
	}
	pthread_mutex_unlock(&lnp_key_store_mutex);
}
/******************************************************************************/
int lnp_set_cipher_in_key(int index, u_char *key) {

	/* Freeing possible existant key. */
	if (lnp_key_store[index].cipher_in_key != NULL) {
		liblog_debug(LAYER_NET,
				"cipher_in_key already exists, freeing.");
		free(lnp_key_store[index].cipher_in_key);
		lnp_key_store[index].cipher_in_key = NULL;
	}
	
	/* Checking if a cipher is assigned to this entry. */
	if (lnp_key_store[index].cipher == NULL) {
		liblog_error(LAYER_NET,
				"no cipher found for this key store entry.");
		return LNP_ERROR;
	}
	
	/* Creating a new key. */
	lnp_key_store[index].cipher_in_key =
			(u_char *)malloc(lnp_key_store[index].cipher->key_length);
	if (lnp_key_store[index].cipher_in_key == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.",
				strerror(errno));
		return LNP_ERROR;
	}
	memcpy(lnp_key_store[index].cipher_in_key, key,
			lnp_key_store[index].cipher->key_length);
	
	liblog_debug(LAYER_NET, "new decryption key set.");
	
	return LNP_OK;
}
/******************************************************************************/
int lnp_set_cipher_in_iv(int index, u_char *iv) {
	
	/* Freeing possible existant iv. */
	if (lnp_key_store[index].cipher_in_iv != NULL) {
		liblog_debug(LAYER_NET,
				"cipher_in_iv already exists, freeing.");
		free(lnp_key_store[index].cipher_in_iv);
		lnp_key_store[index].cipher_in_iv = NULL;
	}
	
	/* Checking if a cipher is assigned to this key store entry. */
	if (lnp_key_store[index].cipher == NULL) {
		liblog_error(LAYER_NET,
				"no cipher found for this key store entry.");
		return LNP_ERROR;
	}
	
	/* Creating a new iv. */
	lnp_key_store[index].cipher_in_iv =
			(u_char *)malloc(lnp_key_store[index].cipher->iv_length);
	if (lnp_key_store[index].cipher_in_iv == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.",
				strerror(errno));
		return LNP_ERROR;
	}
	memcpy(lnp_key_store[index].cipher_in_iv, iv,
			lnp_key_store[index].cipher->iv_length);
	
	liblog_debug(LAYER_NET, "new decryption iv set.");
	
	return LNP_OK;
}
/******************************************************************************/
int lnp_set_cipher_out_key(int index, u_char *key) {
	
	/* Freeing possible existant key. */
	if (lnp_key_store[index].cipher_out_key != NULL) {
		liblog_debug(LAYER_NET,
				"cipher_out_key already exists, freeing.");
		free(lnp_key_store[index].cipher_out_key);
		lnp_key_store[index].cipher_out_key = NULL;
	}
	
	/* Checking if a cipher is assigned to this key store entry. */
	if (lnp_key_store[index].cipher == NULL) {
		liblog_error(LAYER_NET,
				"no cipher found for this key store entry.");
		return LNP_ERROR;
	}
	
	/* Creating a new key. */
	lnp_key_store[index].cipher_out_key =
			(u_char *)malloc(lnp_key_store[index].cipher->key_length);
	if (lnp_key_store[index].cipher_out_key == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.",
				strerror(errno));
		return LNP_ERROR;
	}
	memcpy(lnp_key_store[index].cipher_out_key, key,
			lnp_key_store[index].cipher->key_length);
	
	liblog_debug(LAYER_NET, "new encryption key set.");
	
	return LNP_OK;
}
/******************************************************************************/
int lnp_set_cipher_out_iv(int index, u_char *iv) {

	/* Freeing possible existant iv. */
	if (lnp_key_store[index].cipher_out_iv != NULL) {
		liblog_debug(LAYER_NET,
				"cipher_out_iv already exists, freeing.");
		free(lnp_key_store[index].cipher_out_iv);
		lnp_key_store[index].cipher_out_iv = NULL;
	}
	
	/* Checking if a cipher is assigned to this key store entry. */
	if (lnp_key_store[index].cipher == NULL) {
		liblog_error(LAYER_NET,
				"no cipher found for this key store entry.");
		return LNP_ERROR;
	}
	
	/* Creating a new iv. */
	lnp_key_store[index].cipher_out_iv =
			(u_char *)malloc(lnp_key_store[index].cipher->iv_length);
	if (lnp_key_store[index].cipher_out_iv == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.",
				strerror(errno));
		return LNP_ERROR;
	}
	memcpy(lnp_key_store[index].cipher_out_iv, iv,
			lnp_key_store[index].cipher->iv_length);
	
	liblog_debug(LAYER_NET, "new encryption iv set.");
	
	return LNP_OK;
}
/******************************************************************************/
int lnp_set_mac_in_key(int index, u_char *key) {
	
	/* Freeing possible existant key. */
	if (lnp_key_store[index].mac_in_key != NULL) {
		liblog_debug(LAYER_NET,
				"mac_in_key already exists, freeing.");
		free(lnp_key_store[index].mac_in_key);
		lnp_key_store[index].mac_in_key = NULL;
	}
	
	/* Checking if a MAC function is assigned to this key store entry. */
	if (lnp_key_store[index].mac == NULL) {
		liblog_error(LAYER_NET,
				"no MAC function found for this key store entry.");
		return LNP_ERROR;
	}
	
	/* Creating a new mac key. */
	lnp_key_store[index].mac_in_key =
			(u_char *)malloc(lnp_key_store[index].mac->key_length);
	if (lnp_key_store[index].mac_in_key == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.",
				strerror(errno));
		return LNP_ERROR;
	}
	memcpy(lnp_key_store[index].mac_in_key, key,
			lnp_key_store[index].mac->key_length);
	
	liblog_debug(LAYER_NET, "new MAC verification key set.");
	
	return LNP_OK;
}
/******************************************************************************/
int lnp_set_mac_out_key(int index, u_char *key) {
	
	/* Freeing possible existant key. */
	if (lnp_key_store[index].mac_out_key != NULL) {
		liblog_debug(LAYER_NET,
				"mac_out_key already exists, freeing.");
		free(lnp_key_store[index].mac_out_key);
		lnp_key_store[index].mac_out_key = NULL;
	}
	
	/* Checking if a MAC function is assigned to this key store entry. */
	if (lnp_key_store[index].mac == NULL) {
		liblog_error(LAYER_NET,
				"no MAC function found for this key store entry.");
		return LNP_ERROR;
	}
	
	/* Creating a new mac key. */
	lnp_key_store[index].mac_out_key =
			(u_char *)malloc(lnp_key_store[index].mac->key_length);
	if (lnp_key_store[index].mac_out_key == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.",
				strerror(errno));
		return LNP_ERROR;
	}
	memcpy(lnp_key_store[index].mac_out_key, key,
			lnp_key_store[index].mac->key_length);
	
	liblog_debug(LAYER_NET, "new MAC generation key set.");
	
	return LNP_OK;
}
/******************************************************************************/

