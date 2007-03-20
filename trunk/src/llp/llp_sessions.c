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
 * @file llp_sessions.c Implementations of procedures used to manage sessions.
 * @ingroup llp
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>
#include <util/util_crypto.h>

#include "llp.h"
#include "llp_sessions.h"
#include "llp_packets.h"
#include "llp_data.h"
#include "llp_handshake.h"
#include "llp_nodes.h"
#include "llp_info.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Pointer to function that will handle session closes.
 */
static void (*close_handler)(int session) = NULL;

/*============================================================================*/
/* Public data definitions.                                                   */
/*============================================================================*/

char *llp_states[] = {
		"CLOSED",
		"CONNECTING",
		"BEING CONNECTED",
		"ESTABLISHED",
		"CLOSE WAIT",
		"TIME WAIT"
};

llp_session_t llp_sessions[LLP_MAX_SESSIONS];

pthread_mutex_t llp_sessions_mutexes[LLP_MAX_SESSIONS];

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/	   

int llp_sessions_initialize() {
	int i;
	
	/* Initializing session information. */
	memset(llp_sessions, 0, sizeof(llp_sessions));
	
	liblog_debug(LAYER_LINK, "session information initialized.");

	/* Creating mutexes. */

	for (i = 0; i < LLP_MAX_SESSIONS; i++) {
		if (pthread_mutex_init(&llp_sessions_mutexes[i], NULL) > 0) {
			liblog_error(LAYER_LINK, "error allocating mutex: %s.",
					strerror(errno));
			return LLP_ERROR;
		}
	}
	
	liblog_debug(LAYER_LINK, "mutex initialized.");
	
	return LLP_OK;
}
/******************************************************************************/
void llp_sessions_finalize() {
	int i;
	
	for (i = 0; i < LLP_MAX_SESSIONS; i++) {
		pthread_mutex_lock(&llp_sessions_mutexes[i]);
		llp_close_session(i);
		pthread_mutex_unlock(&llp_sessions_mutexes[i]);		
	}
	
	liblog_debug(LAYER_LINK, "session information resources freed.");
	
	for (i = 0; i < LLP_MAX_SESSIONS; i++) {
		pthread_mutex_destroy(&llp_sessions_mutexes[i]);
	}
	
	liblog_debug(LAYER_LINK, "resources freed.");
	
}
/******************************************************************************/
int llp_set_cipher_in_key(int session, u_char *key) {

	/* Freeing possible existant key. */
	if (llp_sessions[session].cipher_in_key != NULL) {
		liblog_debug(LAYER_LINK,
				"cipher_in_key already exists, freeing.");
		free(llp_sessions[session].cipher_in_key);
		llp_sessions[session].cipher_in_key = NULL;
	}
	
	/* Checking if a cipher is assigned to this session. */
	if (llp_sessions[session].cipher == NULL) {
		liblog_error(LAYER_LINK,
				"no cipher found for this session.");
		return LLP_ERROR;
	}
	
	/* Creating a new key. */
	llp_sessions[session].cipher_in_key =
			(u_char *)malloc(llp_sessions[session].cipher->key_length);
	if (llp_sessions[session].cipher_in_key == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	memcpy(llp_sessions[session].cipher_in_key, key,
			llp_sessions[session].cipher->key_length);
	
	liblog_debug(LAYER_LINK, "new decryption key set.");
	
	return LLP_OK;
}
/******************************************************************************/
int llp_set_cipher_in_iv(int session, u_char *iv) {
	
	/* Freeing possible existant iv. */
	if (llp_sessions[session].cipher_in_iv != NULL) {
		liblog_debug(LAYER_LINK,
				"cipher_in_iv already exists, freeing.");
		free(llp_sessions[session].cipher_in_iv);
		llp_sessions[session].cipher_in_iv = NULL;
	}
	
	/* Checking if a cipher is assigned to this session. */
	if (llp_sessions[session].cipher == NULL) {
		liblog_error(LAYER_LINK,
				"no cipher found for this session.");
		return LLP_ERROR;
	}
	
	/* Creating a new iv. */
	llp_sessions[session].cipher_in_iv =
			(u_char *)malloc(llp_sessions[session].cipher->iv_length);
	if (llp_sessions[session].cipher_in_iv == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	memcpy(llp_sessions[session].cipher_in_iv, iv,
			llp_sessions[session].cipher->iv_length);
	
	liblog_debug(LAYER_LINK, "new decryption iv set.");
	
	return LLP_OK;
}
/******************************************************************************/
int llp_set_cipher_out_key(int session, u_char *key) {
	
	/* Freeing possible existant key. */
	if (llp_sessions[session].cipher_out_key != NULL) {
		liblog_debug(LAYER_LINK,
				"cipher_out_key already exists, freeing.");
		free(llp_sessions[session].cipher_out_key);
		llp_sessions[session].cipher_out_key = NULL;
	}
	
	/* Checking if a cipher is assigned to this session. */
	if (llp_sessions[session].cipher == NULL) {
		liblog_error(LAYER_LINK,
				"no cipher found for this session.");
		return LLP_ERROR;
	}
	
	/* Creating a new key. */
	llp_sessions[session].cipher_out_key =
			(u_char *)malloc(llp_sessions[session].cipher->key_length);
	if (llp_sessions[session].cipher_out_key == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	memcpy(llp_sessions[session].cipher_out_key, key,
			llp_sessions[session].cipher->key_length);
	
	liblog_debug(LAYER_LINK, "new encryption key set.");
	
	return LLP_OK;
}
/******************************************************************************/
int llp_set_cipher_out_iv(int session, u_char *iv) {

	/* Freeing possible existant iv. */
	if (llp_sessions[session].cipher_out_iv != NULL) {
		liblog_debug(LAYER_LINK,
				"cipher_out_iv already exists, freeing.");
		free(llp_sessions[session].cipher_out_iv);
		llp_sessions[session].cipher_out_iv = NULL;
	}
	
	/* Checking if a cipher is assigned to this session. */
	if (llp_sessions[session].cipher == NULL) {
		liblog_error(LAYER_LINK,
				"no cipher found for this session.");
		return LLP_ERROR;
	}
	
	/* Creating a new iv. */
	llp_sessions[session].cipher_out_iv =
			(u_char *)malloc(llp_sessions[session].cipher->iv_length);
	if (llp_sessions[session].cipher_out_iv == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	memcpy(llp_sessions[session].cipher_out_iv, iv,
			llp_sessions[session].cipher->iv_length);
	
	liblog_debug(LAYER_LINK, "new encryption iv set.");
	
	return LLP_OK;
}
/******************************************************************************/
int llp_set_mac_in_key(int session, u_char *key) {
	
	/* Freeing possible existant key. */
	if (llp_sessions[session].mac_in_key != NULL) {
		liblog_debug(LAYER_LINK,
				"mac_in_key already exists, freeing.");
		free(llp_sessions[session].mac_in_key);
		llp_sessions[session].mac_in_key = NULL;
	}
	
	/* Checking if a MAC function is assigned to this session. */
	if (llp_sessions[session].mac == NULL) {
		liblog_error(LAYER_LINK,
				"no MAC function found for this session.");
		return LLP_ERROR;
	}
	
	/* Creating a new iv. */
	llp_sessions[session].mac_in_key =
			(u_char *)malloc(llp_sessions[session].mac->key_length);
	if (llp_sessions[session].mac_in_key == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	memcpy(llp_sessions[session].mac_in_key, key,
			llp_sessions[session].mac->key_length);
	
	liblog_debug(LAYER_LINK, "new MAC verification key set.");
	
	return LLP_OK;
}
/******************************************************************************/
int llp_set_mac_out_key(int session, u_char *key) {
	
	/* Freeing possible existant key. */
	if (llp_sessions[session].mac_out_key != NULL) {
		liblog_debug(LAYER_LINK,
				"mac_out_key already exists, freeing.");
		free(llp_sessions[session].mac_out_key);
		llp_sessions[session].mac_out_key = NULL;
	}
	
	/* Checking if a MAC function is assigned to this session. */
	if (llp_sessions[session].mac == NULL) {
		liblog_error(LAYER_LINK,
				"no MAC function found for this session.");
		return LLP_ERROR;
	}
	
	/* Creating a new key. */
	llp_sessions[session].mac_out_key =
			(u_char *)malloc(llp_sessions[session].mac->key_length);
	if (llp_sessions[session].mac_out_key == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	memcpy(llp_sessions[session].mac_out_key, key,
			llp_sessions[session].mac->key_length);
	
	liblog_debug(LAYER_LINK, "new MAC generation key set.");
	
	return LLP_OK;
}
/******************************************************************************/
int llp_set_verifier(int session, u_char *verifier) {
	
	/* Freeing possible existant key. */
	if (llp_sessions[session].verifier != NULL) {
		liblog_debug(LAYER_LINK,
				"verifier already exists, freeing.");
		free(llp_sessions[session].verifier);
		llp_sessions[session].verifier = NULL;
	}
	
	/* Checking if a MAC function is assigned to this session. */
	if (llp_sessions[session].hash == NULL) {
		liblog_error(LAYER_LINK,
				"no hash function found for this session.");
		return LLP_ERROR;
	}
	
	/* Creating a new key. */
	llp_sessions[session].verifier =
			(u_char *)malloc(llp_sessions[session].hash->length);
	if (llp_sessions[session].verifier == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	memcpy(llp_sessions[session].verifier, verifier,
			llp_sessions[session].hash->length);
	
	liblog_debug(LAYER_LINK, "new verifier set.");
	
	return LLP_OK;
}
/******************************************************************************/
void llp_close_session(int session) {
	
	if (llp_sessions[session].cipher_in_key != NULL) {
		liblog_debug(LAYER_LINK,
				"freeing memory allocated to cipher_in_key.");
		free(llp_sessions[session].cipher_in_key);
		llp_sessions[session].cipher_in_key = NULL;
	}
	
	if (llp_sessions[session].cipher_in_iv != NULL) {
		liblog_debug(LAYER_LINK,
				"freeing memory allocated to cipher_in_iv.");
		free(llp_sessions[session].cipher_in_iv);
		llp_sessions[session].cipher_in_iv = NULL;
	}

	if (llp_sessions[session].cipher_out_key != NULL) {
		liblog_debug(LAYER_LINK,
				"freeing memory allocated to cipher_out_key.");
		free(llp_sessions[session].cipher_out_key);
		llp_sessions[session].cipher_out_key = NULL;
	}
	
	if (llp_sessions[session].cipher_out_iv != NULL) {
		liblog_debug(LAYER_LINK,
				"freeing memory allocated to cipher_out_iv.");
		free(llp_sessions[session].cipher_out_iv);
		llp_sessions[session].cipher_out_iv = NULL;
	}
	
	if (llp_sessions[session].mac_in_key != NULL) {
		liblog_debug(LAYER_LINK,
				"freeing memory allocated to mac_in_key.");
		free(llp_sessions[session].mac_in_key);
		llp_sessions[session].mac_in_key = NULL;
	}
	
	if (llp_sessions[session].mac_out_key != NULL) {
		liblog_debug(LAYER_LINK,
				"freeing memory allocated to mac_out_key.");
		free(llp_sessions[session].mac_out_key);
		llp_sessions[session].mac_out_key = NULL;
	}
	
	if (llp_sessions[session].verifier != NULL) {
		liblog_debug(LAYER_LINK,
				"freeing memory allocated to verifier.");
		free(llp_sessions[session].verifier);
		llp_sessions[session].verifier = NULL;
	}
	
	llp_sessions[session].state = LLP_STATE_CLOSED;
	llp_set_node_inactive(session);	

	/* Calling the registered callback function. */
	if (close_handler != NULL) {
		close_handler(session);
	}
	
	liblog_debug(LAYER_LINK, "session %d is now in CLOSED state.", session);
}
/******************************************************************************/
int llp_get_free_session(int next_state) {
	int i;
	int found = 0;

	for (i = 0; i < LLP_MAX_SESSIONS && !found; i++) {
		if (pthread_mutex_trylock(&llp_sessions_mutexes[i]) != EBUSY) {
			if (llp_sessions[i].state == LLP_STATE_CLOSED) {
				liblog_debug(LAYER_LINK, "free session %d found.", i);
				llp_sessions[i].state = next_state;
				llp_sessions[i].hunt_time = 0;
				llp_sessions[i].silence = 0;				
				found = 1;
			}
			pthread_mutex_unlock(&llp_sessions_mutexes[i]);
		}
	}
	
	return (found ? (i - 1) : LLP_ERROR);
}
/******************************************************************************/
int llp_get_last_error(int session) {
	int error;

	pthread_mutex_lock(&llp_sessions_mutexes[session]);
	error = llp_sessions[session].error;
	pthread_mutex_unlock(&llp_sessions_mutexes[session]);	
	
	return error;
}
/******************************************************************************/
void llp_handle_timeouts() {
	int i;
	
	for (i = 0; i < LLP_MAX_SESSIONS; i++) {
		/* If timeout is zero, the timeout is disabled. */
		if (pthread_mutex_trylock(&llp_sessions_mutexes[i]) == 0) {
			if (llp_sessions[i].state == LLP_STATE_CLOSED) {
				pthread_mutex_unlock(&llp_sessions_mutexes[i]);
				continue;
			}
			if (llp_sessions[i].timeout > 0) {
				llp_sessions[i].timeout--;
				if (llp_sessions[i].timeout == 0) {
					liblog_debug(LAYER_LINK, "session %d timed out.", i);
					llp_close_session(i);
				}
			}
			/* Seeing if this session is expired. */
			llp_sessions[i].alive++;
			if (llp_sessions[i].alive >= (llp_get_expiration_time() *
					LLP_TIME_TICKS_PER_SECOND)) {
				liblog_debug(LAYER_LINK, "session %d expired out.", i);
				llp_disconnect(i);
			}				
			pthread_mutex_unlock(&llp_sessions_mutexes[i]);
		}
	}
}
/******************************************************************************/
void llp_handle_silence() {
	int i;
	
	for (i = LLP_MAX_SESSIONS-1; i >= 0; i--) {
		/* If timeout is zero, the timeout is disabled. */
		if (pthread_mutex_trylock(&llp_sessions_mutexes[i]) == 0) {
			llp_sessions[i].silence++;
			if (llp_sessions[i].silence >= LLP_T_SILENT) {
				if (llp_sessions[i].state == LLP_STATE_ESTABLISHED) {
					llp_keep_session_alive(i);	
				} else {
					if (llp_sessions[i].state == LLP_STATE_CLOSE_WAIT) {
						llp_disconnect(i);
					}
				}
			}
			pthread_mutex_unlock(&llp_sessions_mutexes[i]);
		}
	}
}
/******************************************************************************/
void llp_handle_connections() {
	int i;
	int active;
	int min_connections;
	
	min_connections = llp_get_min_connections();
	active = llp_get_active_sessions_counter();

	if (active < min_connections) {
		for (i = 0; i < min_connections - active; i++) {
			/* Break if the call fail (subsequent calls will fail too). */
			if (llp_connect_any() == LLP_ERROR) {
				break;
			}
		}
	}
}
/******************************************************************************/
int llp_register_close(void (*handler)(int session)) {
	if (close_handler == NULL) {
		close_handler = handler;
		return LINK_OK;
	}
	
	return LINK_ERROR;
}
/******************************************************************************/
int llp_unregister_close() {
	if (close_handler == NULL) {
		return LINK_ERROR;
	}
	
	close_handler = NULL;
	return LINK_OK;
}
/******************************************************************************/
