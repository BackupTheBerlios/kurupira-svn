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
 * @file llp_handshake.c Implementation of functions used to establish a new
 * 		connection.
 * @ingroup llp
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

#include <libfreedom/types.h>
#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>
#include <util/util.h>
#include <util/util_data.h>
#include <util/util_crypto.h>
#include <util/util_keys.h>

#include "llp_handshake.h"
#include "llp_sessions.h"
#include "llp_packets.h"
#include "llp_config.h"
#include "llp_nodes.h"
#include "llp_info.h"
#include "llp_dh.h"
#include "llp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Pointer to function that will handle new connections' events.
 */
static void (*connect_handler)(int session) = NULL;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * Creates the verifier used in session closing.
 * 
 * @param session - the session to compute the verifier.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
static int compute_verifier(int session);

/*
 * Creates the needed keys for a session using its session information.
 * 
 * @param session - the session to create the keys.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
static int create_keys(int session);

/*
 * Checks if the remote and local protocol versions are compatible.
 * 
 * @param remote_major - major version of remote node's protocol implementation.
 * @param remote_minor - minor version of remote node's protocol implementation.
 * @return LLP_OK if the protocols are compatible, LLP_ERROR otherwise.
 */
static int verify_versions(u_char remote_major, u_char remote_minor);

/**
 * Sends a LLP_CONNECTION_REQUEST packet.
 * 
 * @param session - the session to send the packet.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
static inline int send_connection_request(int session);

/*
 * Sends a LLP_CONNECTION_OK packet, trying to connect to the port specified in
 * the UDP header of the LLP_CONNECTION_REQUEST packet.
 * 
 * @param session - the session to send the packet.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
static inline int send_connection_ok(int session);

/*
 * Sends a LLP_KEY_EXCHANGE packet.
 * 
 * @param session - the session to send the packet.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
static inline int send_key_exchange(int session);

/*
 * Reads the contents of a LLP_CONNECTION_REQUEST into packet.
 * 
 * @param packet - packet representing the parsed data.
 * @param packet_data - data to parse.
 * @param packet_length - length of the packet buffer, in bytes.
 * @return LLP_OK if no parsing errors occurred, LLP_ERROR otherwise.
 */
static inline int parse_connection_request(llp_packet_p *packet, 
		u_char *packet_data, int packet_length);
		
/*
 * Reads the contents of a LLP_CONNECTION_OK into packet.
 * 
 * @param packet - packet representing the parsed data.
 * @param packet_data - data to parse.
 * @param packet_length - length of the packet buffer, in bytes.
 * @return LLP_OK if no parsing errors occurred, LLP_ERROR otherwise.
 */
static inline int parse_connection_ok(llp_packet_p *packet, u_char *packet_data,
		int packet_length);
		
/*
 * Reads the contents of a LLP_KEY_EXCHANGE into packet.
 * 
 * @param packet - packet representing the parsed data.
 * @param packet_data - data to parse.
 * @param packet_length - length of the packet buffer, in bytes.
 * @return LLP_OK if no parsing errors occurred, LLP_ERROR otherwise.
 */
static int parse_key_exchange(llp_packet_p *packet, u_char *packet_data,
		int packet_length);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_handle_connection_request(u_char *packet_data, int packet_length,
		struct sockaddr_in *peer) {
	int session;
	int return_value;
	llp_packet_p packet;

	/* Seeing if the new connection won't trespass the connection limit. */
	if (llp_get_active_sessions_counter() >= llp_get_max_connections()) {
		liblog_warn(LAYER_LINK, "maximum number of connections reached.");
		return LLP_ERROR;
	}

	if (parse_connection_request(&packet, packet_data, packet_length)
			== LLP_ERROR) {
		liblog_debug(LAYER_LINK, "packet format corrupted.");	
		return LLP_ERROR;
	} 

	/* Verifying protocol versions. */
	if (verify_versions(packet.llp_connection_request.major_version,
			packet.llp_connection_request.minor_version) == LLP_ERROR) {
		return LLP_ERROR;
	}
	
	/* Checking if this node is already connected. */
	if (llp_get_session_by_address(peer) != LLP_ERROR) {
		liblog_error(LAYER_LINK, "node already connected.");
		return LLP_ERROR;
	}

	/* Reserving a session to this connection. */
	session = llp_get_free_session(LLP_STATE_BEING_CONNECTED);
	if (session == LLP_ERROR) {
		liblog_warn(LAYER_LINK, "no free sessions available.");
		return LLP_ERROR;
	}
	liblog_debug(LAYER_LINK, "using session: %d.", session);
	
	llp_lock_session(session);

	/* Fill up the session info. */
	/* The port is extracted from the packet header. */
	memcpy(&llp_sessions[session].address, peer, sizeof(struct sockaddr_in));
	llp_sessions[session].foreign_session =
			packet.llp_connection_request.session;
	llp_sessions[session].cipher = 
			llp_cipher_search(packet.llp_connection_request.ciphers);
	llp_sessions[session].hash =
			llp_hash_search(packet.llp_connection_request.hashes);
	llp_sessions[session].mac =
			llp_mac_search(packet.llp_connection_request.macs);
	memcpy(llp_sessions[session].h_in, packet.llp_connection_request.h,
			LLP_H_LENGTH);	

	/* Functions received don't support even the defaults. */
	if (llp_sessions[session].cipher == NULL ||
			llp_sessions[session].hash == NULL ||
			llp_sessions[session].mac == NULL) {
		liblog_error(LAYER_LINK,
				"received functions not supported, packet dropped.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	liblog_debug(LAYER_LINK, "received functions are supported.");
	
	llp_sessions[session].encrypted = (
			strncmp(llp_sessions[session].cipher->name, UTIL_NULL_CIPHER,
			strlen(UTIL_NULL_CIPHER)) == 0 ?
			LLP_SESSION_NOT_ENCRYPTED : LLP_SESSION_ENCRYPTED);

	liblog_debug(LAYER_LINK, "session %d is now in BEING_CONNECTED state.",
			session);

	/* Generating Diffie & Hellman parameters. */
	if (llp_compute_dh_params(llp_sessions[session].x,
			llp_sessions[session].y_out) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating D&H parameters.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	/* Generatin h_out parameter. */
	if (util_rand_bytes(llp_sessions[session].h_out, LLP_H_LENGTH)
			== UTIL_ERROR) {
		liblog_error(LAYER_LINK, "error generating h parameter.");
		return_value = LLP_ERROR;
		goto return_label;		
	};
	
	/* Send request packet. */
	if (send_connection_ok(session) == LLP_ERROR) {
		return_value = LLP_ERROR;
		goto return_label;
	}
	liblog_debug(LAYER_LINK, "LLP_CONNECTION_OK packet sent.");

	return_value = LLP_OK;

return_label:

	if (return_value == LLP_ERROR) {
		llp_close_session(session);
	}
	llp_unlock_session(session);

	return return_value;
}
/******************************************************************************/
int llp_handle_connection_ok(u_char *packet_data, int packet_length) {
	int session;
	int return_value;
	llp_packet_p packet;

	/* Reading packet */
	if (parse_connection_ok(&packet, packet_data, packet_length) == LLP_ERROR) {
		liblog_debug(LAYER_LINK, "packet format corrupted.");	
		return LLP_ERROR;
	} 

	session = packet.llp_connection_ok.session_dst;
	llp_lock_session(session);
	
	/* Fill up the session info. */
	llp_sessions[session].state = LLP_STATE_ESTABLISHED;
	llp_sessions[session].foreign_session = packet.llp_connection_ok.session_src;
	llp_sessions[session].timeout = LLP_T_TIMEOUT;
	llp_sessions[session].silence = 0;
	llp_sessions[session].hunt_time = 0;
	llp_sessions[session].alive = 0;
	llp_sessions[session].error = LLP_OK;
	llp_sessions[session].cipher =
			llp_cipher_search(packet.llp_connection_ok.cipher);
	llp_sessions[session].hash = llp_hash_search(packet.llp_connection_ok.hash);
	llp_sessions[session].mac = llp_mac_search(packet.llp_connection_ok.mac);	
	llp_sessions[session].encrypted = (
			strncmp(llp_sessions[session].cipher->name, UTIL_NULL_CIPHER,
			strlen(UTIL_NULL_CIPHER)) == 0 ?
			LLP_SESSION_NOT_ENCRYPTED : LLP_SESSION_ENCRYPTED);
	memcpy(llp_sessions[session].h_in, packet.llp_connection_ok.h,
			LLP_H_LENGTH);
	memcpy(llp_sessions[session].y_in, packet.llp_connection_ok.y,
			LLP_Y_LENGTH);

	/* Setting node state in nodes cache. */
	llp_set_node_active(&llp_sessions[session].address, session);
	
	/* Correcting number of active sessions. */
	llp_add_active_sessions_counter(1);
	
	liblog_debug(LAYER_LINK, "session %d is now in ESTABLISHED state.",
			session);

	/* Functions received don't support even the defaults. */
	if (llp_sessions[session].cipher == NULL ||
			llp_sessions[session].hash == NULL ||
			llp_sessions[session].mac == NULL) {
		liblog_error(LAYER_LINK,
				"received function not supported, packet dropped.");
		return_value = LLP_ERROR;
		goto return_label;		
	}
	liblog_debug(LAYER_LINK, "received functions are supported.");

	if (llp_compute_dh_params(llp_sessions[session].x,
			llp_sessions[session].y_out) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating D&H parameters.");
		return_value = LLP_ERROR;
		goto return_label;		
	}
	
	/* Computing Diffie & Hellman shared secret z. */
	if (llp_compute_dh_secret(llp_sessions[session].z, 
			llp_sessions[session].y_in, llp_sessions[session].x) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating D&H secret.");
		return_value = LLP_ERROR;
		goto return_label;				
	}
	
	/* Compute verifier. */
	if (compute_verifier(session) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating verifier.");
		return_value = LLP_ERROR;
		goto return_label;				
	}

	/* Create all the keys. */
	if (create_keys(session) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating session keys.");
		return_value = LLP_ERROR;
		goto return_label;				
	};
	
	/* Send key exchange packet. */
	if (send_key_exchange(session) == LLP_ERROR) {
		return_value = LLP_ERROR;
		goto return_label;		
	}
	liblog_debug(LAYER_LINK, "LLP_KEY_EXCHANGE packet sent.");

	llp_unlock_session(session);

	/* Calling the registered callback function. */
	if (connect_handler != NULL) {
		connect_handler(session);
	}

	return_value = LLP_OK;

return_label:

	if (return_value == LLP_ERROR) {
		llp_close_session(session);
	}
	llp_unlock_session(session);

	return return_value;
}
/******************************************************************************/
int llp_handle_key_exchange(u_char *packet_data, int packet_length) {
	int session;
	int return_value;
	llp_packet_p packet;
	
	/* Reading packet */
	if (parse_key_exchange(&packet, packet_data, packet_length)	== LLP_ERROR) {
		liblog_debug(LAYER_LINK, "packet format corrupted.");	
		return LLP_ERROR;
	} 
	liblog_debug(LAYER_LINK, "packet successfuly parsed.");	
	
	session = packet.llp_key_exchange.session;
	llp_lock_session(session);
	
	/* Updating the session info. */
	llp_sessions[session].state = LLP_STATE_ESTABLISHED;
	llp_sessions[session].timeout = LLP_T_TIMEOUT;
	llp_sessions[session].alive = 0;
	llp_sessions[session].error = LLP_OK;
	memcpy(llp_sessions[session].y_in, packet.llp_key_exchange.y,
			LLP_Y_LENGTH);

	/* Adding node to cache. */
	llp_add_node_to_cache(&llp_sessions[session].address);
	llp_set_node_active(&llp_sessions[session].address, session);
	
	/* Correcting number of active sessions. */
	llp_add_active_sessions_counter(1);
	
	/* Computing Diffie & Hellman shared secret z. */
	if (llp_compute_dh_secret(llp_sessions[session].z, 
			llp_sessions[session].y_in,	llp_sessions[session].x) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating D&H secret.");
		return_value = LLP_ERROR;
		goto return_label;						
	}
	liblog_debug(LAYER_LINK, "D&H secret z computed.");
	
	/* Compute verifier. */
	if (compute_verifier(session) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating verifier.");
		return_value = LLP_ERROR;
		goto return_label;				
	}

	/* Create all the keys. */
	if (create_keys(session) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating session keys.");
		return_value = LLP_ERROR;
		goto return_label;						
	};
	liblog_debug(LAYER_LINK, "keys created.");
	
	liblog_debug(LAYER_LINK, "session %d is now in ESTABLISHED state.",
			session);
	
	llp_unlock_session(session);

	/* Calling the registered callback function. */
	if (connect_handler != NULL) {
		connect_handler(session);
	}

	return_value = LLP_OK;

return_label:

	if (return_value == LLP_ERROR) {
		llp_close_session(session);
	}
	llp_unlock_session(session);

	return return_value;
}
/******************************************************************************/
int llp_connect_to(struct sockaddr_in *address) {
	int session;
	int return_value;
	
	/* Seeing if the new connection won't trespass the connection limit. */
	if (llp_get_active_sessions_counter() >= llp_get_max_connections()) {
		liblog_warn(LAYER_LINK, "maximum number of connections reached.");
		return LLP_ERROR;
	}
	
	/* Checking if this node is already connected. */
	if (llp_get_session_by_address(address) != LLP_ERROR) {
		liblog_error(LAYER_LINK, "node already connected.");
		return LLP_ERROR;
	}
	
	/* Getting a free session identifier. */
	session = llp_get_free_session(LLP_STATE_CONNECTING);
	if (session == LLP_ERROR) {
		liblog_warn(LAYER_LINK, "no free sessions available.");
		return LLP_ERROR;
	}
	liblog_debug(LAYER_LINK, "using session: %d.", session);
	
	llp_lock_session(session);
	
	/* Generating h_out. */
	if (util_rand_bytes(llp_sessions[session].h_out, LLP_H_LENGTH)
			== UTIL_ERROR) {
		liblog_error(LAYER_LINK, "can't generate random bytes for h.");
		llp_close_session(session);
		llp_unlock_session(session);
		return LLP_ERROR;
	}
	liblog_debug(LAYER_LINK, "parameter h_out generated.");
	
	/* Fix session info. */
	llp_sessions[session].address.sin_family = AF_INET;
	llp_sessions[session].address.sin_port = address->sin_port;
	memcpy(&llp_sessions[session].address.sin_addr, &address->sin_addr,
			sizeof(struct in_addr));
	llp_sessions[session].timeout = LLP_T_TIMEOUT;
	liblog_debug(LAYER_LINK, "session %d is now in CONNECTING state.",
			session);
	
	/* Adding node to cache. */
	llp_add_node_to_cache(&llp_sessions[session].address);
	llp_set_node_connecting(&llp_sessions[session].address, session);
	return_value = send_connection_request(session);
	
	llp_unlock_session(session);
	
	if (return_value == LLP_ERROR) {
		llp_close_session(session);
		return LLP_ERROR;
	}
	
	return LLP_OK;
}
/******************************************************************************/
int llp_connect_any() {
	struct sockaddr_in address;
	
	if (llp_get_nodes_from_cache(1, &address) == LLP_ERROR)
		return LLP_ERROR;
	return llp_connect_to(&address);
}
/******************************************************************************/
int llp_register_connect(void (*handler)(int session)) {
	if (connect_handler == NULL) {
		connect_handler = handler;
		return LLP_OK;
	}
	
	return LLP_ERROR;
}
/******************************************************************************/
int llp_unregister_connect() {
	if (connect_handler == NULL) {
		return LLP_ERROR;
	}
	
	connect_handler = NULL;
	return LLP_OK;
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int compute_verifier(int session) {
	u_char *verifier;
	int hash_length;
	
	hash_length = llp_sessions[session].hash->length;
	
	verifier = (u_char *)malloc(hash_length);
	if (verifier == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s", strerror(errno));
		return LLP_ERROR;
	}
	
	/* Computing HASH(z). */
	llp_sessions[session].hash->function(verifier, llp_sessions[session].z,
			hash_length);
	
	if (llp_set_verifier(session, verifier) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating verifier.");
		free(verifier);
		return LLP_ERROR;
	}
	
	liblog_debug(LAYER_LINK, "verifier generated.");
	
	free(verifier);
	return LLP_OK;
}
/******************************************************************************/
int create_keys(int session) {
	u_char *cipher_key;
	u_char *cipher_iv;
	u_char *mac_key;
	int return_value;
	
	/* Allocating memory for temporary key containers. */
	cipher_key = (u_char *)malloc(llp_sessions[session].cipher->key_length);
	cipher_iv = (u_char *)malloc(llp_sessions[session].cipher->iv_length);
	mac_key = (u_char *)malloc(llp_sessions[session].mac->key_length);
	
	if (cipher_key == NULL || cipher_iv == NULL || mac_key == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s", strerror(errno));
		return_value = LLP_ERROR;
		goto return_label;
	}

	if (util_create_key(
			cipher_key, 
			llp_sessions[session].cipher->key_length,
			llp_sessions[session].z,
			llp_sessions[session].h_in,
			LLP_H_LENGTH,
			"key",
			llp_sessions[session].hash) == LLP_ERROR
				|| llp_set_cipher_in_key(session, cipher_key) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating cipher_in_key.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	if (util_create_key(
			cipher_iv, 
			llp_sessions[session].cipher->iv_length,
			llp_sessions[session].z,
			llp_sessions[session].h_in,
			LLP_H_LENGTH,
			"iv",
			llp_sessions[session].hash) == LLP_ERROR
				|| llp_set_cipher_in_iv(session, cipher_iv) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating cipher_in_iv.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	if (util_create_key(
			cipher_key, 
			llp_sessions[session].cipher->key_length,
			llp_sessions[session].z,
			llp_sessions[session].h_out,
			LLP_H_LENGTH,
			"key",
			llp_sessions[session].hash) == LLP_ERROR
				|| llp_set_cipher_out_key(session, cipher_key) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating cipher_out_key.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	if (util_create_key(
			cipher_iv, 
			llp_sessions[session].cipher->iv_length,
			llp_sessions[session].z,
			llp_sessions[session].h_out,
			LLP_H_LENGTH,
			"iv",
			llp_sessions[session].hash) == LLP_ERROR
				|| llp_set_cipher_out_iv(session, cipher_iv) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating cipher_out_iv.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	if (util_create_key(
			mac_key, 
			llp_sessions[session].mac->key_length,
			llp_sessions[session].z,
			llp_sessions[session].h_in,
			LLP_H_LENGTH,
			"mac",
			llp_sessions[session].hash) == LLP_ERROR
				|| llp_set_mac_in_key(session, mac_key) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating mac_in_key.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	if (util_create_key(
			mac_key, 
			llp_sessions[session].mac->key_length,
			llp_sessions[session].z,
			llp_sessions[session].h_out,
			LLP_H_LENGTH,
			"mac",
			llp_sessions[session].hash) == LLP_ERROR
				|| llp_set_mac_out_key(session, mac_key) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating mac_out_key.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	return_value = LLP_OK;

return_label:

	free(cipher_key);
	free(cipher_iv);
	free(mac_key);
	return LLP_ERROR;
}
/******************************************************************************/
int verify_versions(u_char remote_major, u_char remote_minor) {
	/*
	 * Boolean that controls if a log message informing about a new LLP version 
	 * was found when a connection was being established with some host.
	 */
	static int new_version_found = 0;
	
	/* Testing protocol major version implemented by remote peer. */
	if (remote_major != LLP_MAJOR_VERSION) {
		liblog_warn(LAYER_LINK,
				"incompatible protocol versions: local: %d.%d; remote: %d.%d",
				LLP_MAJOR_VERSION, LLP_MINOR_VERSION, 
				remote_major, remote_minor);
		if (remote_major > LLP_MAJOR_VERSION) {
			liblog_info(LAYER_LINK,
					"remote peer uses version %d.%d, upgrade mandatory.",
				remote_major, remote_minor);
				new_version_found = 1;			
		}
		return LLP_ERROR;
	}
	/* Comparing minor versions. */
	if (remote_minor > LLP_MINOR_VERSION &&	!new_version_found) {
		liblog_info(LAYER_LINK,
				"remote peer uses version %d.%d, upgrade recommended.",
				remote_major, remote_minor);
		new_version_found = 1;
	}

	return LLP_OK;
}
/******************************************************************************/
int send_connection_request(int session) {
	int local_port;
	u_char packet[LLP_CONNECTION_REQUEST_MAX_LENGTH];
	char cipher_string[LLP_FUNCTION_LIST_MAX_LENGTH];
	char hash_string[LLP_FUNCTION_LIST_MAX_LENGTH];
	char mac_string[LLP_FUNCTION_LIST_MAX_LENGTH];
		
	/* Getting local port. */
	local_port = llp_get_port();

	llp_get_cipher_string(cipher_string, LLP_FUNCTION_LIST_MAX_LENGTH);
	llp_get_hash_string(hash_string, LLP_FUNCTION_LIST_MAX_LENGTH);
	llp_get_mac_string(mac_string, LLP_FUNCTION_LIST_MAX_LENGTH);

	/* Constructing connection request packet */
	UTIL_WRITE_START(packet)
	UTIL_WRITE_BYTE  (LLP_CONNECTION_REQUEST)
	UTIL_WRITE_BYTE  (LLP_MAJOR_VERSION)
	UTIL_WRITE_BYTE  (LLP_MINOR_VERSION)
	UTIL_WRITE_BYTE  (session)
	UTIL_WRITE_STRING(cipher_string)
	UTIL_WRITE_STRING(hash_string)
	UTIL_WRITE_STRING(mac_string)
	UTIL_WRITE_BYTES (llp_sessions[session].h_out, LLP_H_LENGTH)
	
	/* Sending packet. */
	if (llp_send_session_packet(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error sending packet.");
		llp_close_session(session);
		return LLP_ERROR;
	}
	liblog_debug(LAYER_LINK, "packet sent.");
	
	return LLP_OK;
}
/******************************************************************************/
int send_connection_ok(int session) {
	u_char packet[LLP_CONNECTION_OK_MAX_LENGTH];
	
	/* Constructing connection acknowledgement packet. */
	UTIL_WRITE_START (packet)
	UTIL_WRITE_BYTE  (LLP_CONNECTION_OK)
	UTIL_WRITE_BYTE  (llp_sessions[session].foreign_session)
	UTIL_WRITE_BYTE  (session)
	UTIL_WRITE_STRING(llp_sessions[session].cipher->name)
	UTIL_WRITE_STRING(llp_sessions[session].hash->name)
	UTIL_WRITE_STRING(llp_sessions[session].mac->name)
	UTIL_WRITE_BYTES (llp_sessions[session].h_out, LLP_H_LENGTH)
	UTIL_WRITE_MPINT (llp_sessions[session].y_out)
	
	/* Sending packet. */
	if (llp_send_session_packet(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error sending packet.");
		return LLP_ERROR;
	}
	liblog_debug(LAYER_LINK, "packet sent.");

	return LLP_OK;
}
/******************************************************************************/
int send_key_exchange(int session) {
	u_char packet[LLP_KEY_EXCHANGE_MAX_LENGTH];

	/* Constructing key exchange packet. */
	UTIL_WRITE_START (packet)
	UTIL_WRITE_BYTE  (LLP_KEY_EXCHANGE)
	UTIL_WRITE_BYTE  (llp_sessions[session].foreign_session)
	UTIL_WRITE_MPINT (llp_sessions[session].y_out)
	
	/* Sending packet. */
	if (llp_send_session_packet(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		liblog_debug(LAYER_LINK, "error sending packet.");
		return LLP_ERROR;
	}
	
	liblog_debug(LAYER_LINK, "packet sent.");

	return LLP_OK;
}
/******************************************************************************/
int parse_connection_request(llp_packet_p *packet, u_char *packet_data, 
		int packet_size) {
	
	UTIL_READ_START(packet_data, packet_size, LLP_OK, LLP_ERROR)
	UTIL_READ_BYTE(packet->type)
	UTIL_READ_BYTE(packet->llp_connection_request.major_version)
	UTIL_READ_BYTE(packet->llp_connection_request.minor_version)
	UTIL_READ_BYTE(packet->llp_connection_request.session)
	UTIL_READ_STRING(packet->llp_connection_request.ciphers)
	UTIL_READ_STRING(packet->llp_connection_request.hashes)
	UTIL_READ_STRING(packet->llp_connection_request.macs)
	UTIL_READ_BYTES(packet->llp_connection_request.h, LLP_H_LENGTH)
	UTIL_READ_END
}	
/******************************************************************************/
int parse_connection_ok(llp_packet_p *packet, u_char *packet_data,
		int packet_length) {
	
	UTIL_READ_START(packet_data, packet_length, LLP_OK, LLP_ERROR)
	UTIL_READ_BYTE(packet->type)
	UTIL_READ_BYTE(packet->llp_connection_ok.session_dst)
	UTIL_READ_BYTE(packet->llp_connection_ok.session_src)
	UTIL_READ_STRING(packet->llp_connection_ok.cipher)
	UTIL_READ_STRING(packet->llp_connection_ok.hash)
	UTIL_READ_STRING(packet->llp_connection_ok.mac)
	UTIL_READ_BYTES(packet->llp_connection_ok.h, LLP_H_LENGTH)
	UTIL_READ_MPINT(packet->llp_connection_ok.y)
	UTIL_READ_END
}
/******************************************************************************/
int parse_key_exchange(llp_packet_p *packet, u_char *packet_data,
		int packet_length) {
	UTIL_READ_START(packet_data, packet_length, LLP_OK, LLP_ERROR)
	UTIL_READ_BYTE(packet->type)
	UTIL_READ_BYTE(packet->llp_key_exchange.session)
	UTIL_READ_MPINT(packet->llp_key_exchange.y)
	UTIL_READ_END
}
/******************************************************************************/
