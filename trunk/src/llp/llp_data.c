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
 * @file llp_data.c Implementation of functions used to manipulate LLP_DATA
 * 		packets.
 * @ingroup llp
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

#include <libfreedom/liblog.h>
#include <util/util_crypto.h>
#include <util/util_data.h>
#include <util/util.h>

#include "llp.h"
#include "llp_data.h"
#include "llp_nodes.h"
#include "llp_packets.h"
#include "llp_sessions.h"
#include "llp_info.h"
#include "llp_queue.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/**
 * Max value of an unsigned char.
 */
#define MAX_CHAR			255

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/**
 * Sends an LLP_DATA packet, given its contents.
 * 
 * @param[in] session 	- the session used to send the packet.
 * @param[in] data 		- the data to encapsulate in a LLP_DATA packet.
 * @param[in] length 	- the length of data in bytes.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int send_data(int session, u_char *data, int length);

/**
 * Sends an LLP_DATAGRAM packet.
 * 
 * @param[in] session 	- the session used to send the packet.
 * @param[in] data 		- the data to encapsulate in a LLP_DATAGRAM packet.
 * @param[in] length 	- the length of data in bytes.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int send_datagram(int session, u_char *datagram, int length);

/**
 * Sends a packet with a LLP_CLOSE_* pattern.
 * 
 * @param[in] session 	- the session used to send the packet.
 * @param[in] type 		- the type of LLP_CLOSE_* packet.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int send_close(int session, u_char type);

/**
 * Sends an LLP_CLOSE_OK packet.
 * 
 * @param[in] session 	- the session used to send the packet.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int send_close_ok(int session);

/*
 * Sends an LLP_CLOSE_REQUEST packet.
 * 
 * @param[in] session - the session used to send the packet.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
static int send_close_request(int session);

/**
 * Sends an LLP_NODE_HUNT packet.
 * 
 * @param[in] session 	- the session used to send the packet.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int send_node_hunt(int session);

/*
 * Sends a LLP_HUNT_RESULT packet.
 * 
 * @param[in] session 	-the session used to send the packet.
 * @param[in] addresses - addresses of known hosts.
 * @param[in] number 	- number of addresses being sent.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int send_hunt_result(int session, 
	struct sockaddr_in *addresses, int number);

/**
 * Sends an LLP_KEEP_ALIVE packet.
 * 
 * @param session[in] 	- the session used to send the packet.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int send_keep_alive(int session);

/**
 * Handles the encrypted portion of the packet.
 * 
 * @param[in] content 	- the encrypted portion of the LLP_DATA packet.
 * @param[in] length 	- the length of the encrypted content, in bytes.
 * @param[in] mac 		- the LLP_DATA plaintext's MAC value.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */ 
static int handle_encrypted_content(u_char *content, int length, u_char *mac,
	int session);

/**
 * Handles the packet carried inside the LLP_DATA packet.
 * 
 * @param[in] content	- the content (not encrypted) of the LLP_DATA packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_content(u_char *content, int length, int session);

/**
 * Handles the LLP_DATAGRAM packet carried inside the LLP_DATA packet.
 * 
 * @param[in] content	- the content of the LLP_DATAGRAM packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_datagram(u_char *content, int length, int session);

/**
 * Handles the process of verify the authenticity of a LLP_CLOSE_REQUEST packet
 * or LLP_CLOSE_OK packet.
 * 
 * @param[in] content 	- the content of the LLP_CLOSE_* packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_closing(u_char *content, int length, int session);

/**
 * Handles the LLP_CLOSE_REQUEST packet carried inside the LLP_DATA packet.
 * 
 * @param[in] content 	- the content of the LLP_CLOSE_REQUEST packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_close_request(u_char *content, int length, int session);

/**
 * Handles the LLP_CLOSE_OK packet carried inside the LLP_DATA packet.
 * 
 * @param[in] content 	- the content of the LLP_CLOSE_OK packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_close_ok(u_char *content, int length, int session);

/**
 * Handles the LLP_NODE_HUNT packet carried inside the LLP_DATA packet.
 * 
 * @param[in] content 	- the content of the LLP_NODE_HUNT packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_node_hunt(u_char *content, int length, int session);

/**
 * Handles the LLP_HUNT_RESULT packet carried inside the LLP_DATA packet.
 * 
 * @param[in] content 	- the content of the LLP_HUNT_RESULT packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_hunt_result(u_char *content, int length, int session);

/**
 * Handles the LLP_KEEP_ALIVE packet carried inside the LLP_DATA packet.
 * 
 * @param[in] content 	- the content of the LLP_KEEP_ALIVE packet.
 * @param[in] length 	- the content length of the packet, in bytes.
 * @param[in] session 	- the session that the packet was received.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static int handle_keep_alive(u_char *content, int content_length, int session);

/**
 * Reads the contents of a LLP_HUNT_RESULT into packet.
 * 
 * @param[out] packet	- packet representing the parsed data.
 * @param[in] data 		- data to parse.
 * @param[in] length 	- length of the packet buffer, in bytes.
 * @retval LLP_OK 		- if no errors occurred
 * @retval LLP_ERROR	- otherwise
 */
static inline int parse_hunt_result(llp_data_p *packet, u_char *data,
		int length);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_handle_data(u_char *packet_data, int packet_length) {
	int content_length;
	int mac_length;
	int session;
	int offset;
	int return_value;
	llp_packet_p packet;
	u_char *content = NULL;
	u_char *mac = NULL;
	
	/* Reading beginning of packet. */
	/* No need to use safe reading functions, because llp_listen_socket discards
	 * packets that are lesser than 5 bytes in length, and only those packet
	 * could harm the parser behavior. */
	offset = 0;
	util_read_byte(&packet.type, &offset, packet_data);
	util_read_byte(&packet.llp_data.session, &offset, packet_data);

	session = packet.llp_data.session;

	llp_lock_session(session);
	switch(llp_sessions[session].state) {
		case LLP_STATE_CLOSED:
		case LLP_STATE_CONNECTING:
		case LLP_STATE_BEING_CONNECTED:
			liblog_error(LAYER_LINK,
					"packet received in a not established session."
					" Packet dropped.");
			return_value = LLP_ERROR;
			goto return_label;
	}

	/* Calculating lengths before using them */
	mac_length = llp_sessions[session].mac->length;
	content_length = packet_length - mac_length - sizeof(u_short);
	
	/* Check if this packet is too small to be valid. */
	if (content_length < sizeof(u_char) + sizeof(u_short)) {
		/* Packet is smaller than an LLP_KEEP_ALIVE packet. */
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	/* Allocating memory for packet. */
	content = (u_char *)malloc(content_length);
	mac = (u_char *)malloc(mac_length);
	if (content == NULL || mac == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	/* Reading rest of packet. */
	/* No nead to use safe reading functions, because the lengths are
	 * computed using the packet length. */
	util_read_bytes(content, &offset, packet_data, content_length);
	util_read_bytes(mac, &offset, packet_data, mac_length);
	
	/* Handle the content. */
	if (handle_encrypted_content(content, content_length, mac, session)
			== LLP_ERROR) {
		liblog_error(LAYER_LINK, "error handling data content.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	/* Update the session info */
	llp_sessions[session].packets_received++;
	
	/* Timeout is only resetted if the session is not being closed. This way
	 * if a LLP_CLOSE_OK packet is not received, the timeouts threads will
	 * close it automatically. */
	if (llp_sessions[session].state != LLP_STATE_CLOSE_WAIT) {
		llp_sessions[session].timeout = LLP_T_TIMEOUT;
	}

	return_value = LLP_OK;
	
return_label:
	
	llp_unlock_session(session);
	free(content);
	free(mac);

	return return_value;
}
/******************************************************************************/
int llp_keep_session_alive(int session) {
	int return_value;
	
	llp_lock_session(session);
	if (llp_sessions[session].state == LLP_STATE_ESTABLISHED) {
		return_value = send_keep_alive(session);
	} else {
		liblog_error(LAYER_LINK, "the session is not established.");
		return_value = LLP_ERROR;
	}
	llp_unlock_session(session);
	
	return return_value;
}
/******************************************************************************/
int llp_hunt_for_nodes(int session) {
	int return_value;
	struct timeval time;
	struct timezone timezone;
	
	llp_lock_session(session);
	if (llp_sessions[session].state == LLP_STATE_ESTABLISHED) {
		return_value = send_node_hunt(session);
	} else {
		liblog_error(LAYER_LINK, "the session is not established.");
		return_value = LLP_ERROR;
	}
	
	gettimeofday(&time, &timezone);
	llp_sessions[session].hunt_time = time.tv_sec;
	llp_unlock_session(session);;
	
	return return_value;
}
/******************************************************************************/
int llp_disconnect(int session) {
	int return_value;

	liblog_debug(LAYER_LINK, "disconnecting session %d.", session);

	llp_lock_session(session);
	/* Only sessions established or that are waiting a LLP_CLOSE_OK packet
	 * can be disconnected. */
	if (llp_sessions[session].state == LLP_STATE_ESTABLISHED || 
			llp_sessions[session].state == LLP_STATE_CLOSE_WAIT) {
		llp_sessions[session].state = LLP_STATE_CLOSE_WAIT;
	} else {
		liblog_error(LAYER_LINK, "session is not established.", session);
		llp_unlock_session(session);
		return LLP_ERROR;
	} 		
	return_value = send_close_request(session);
	llp_unlock_session(session);
	
	/* Correcting number of active sessions. */
	llp_add_active_sessions_counter(-1);
	
	return return_value;
}
/******************************************************************************/
int llp_read(int *session, u_char *data, int max) {
	int return_value = llp_dequeue_datagram(session, data, max);
	return (return_value == LLP_ERROR ? LINK_ERROR : return_value);
}
/******************************************************************************/
int llp_flush() {
	int session;
	int return_value = 0;
	
	while (llp_try_dequeue_datagram(&session, NULL, -1) != LLP_ERROR) {
		return_value++;
	}
	return return_value;
}
/******************************************************************************/
int llp_write(int session, u_char *data, int length) {
	int return_value;

	llp_lock_session(session);
	if (llp_sessions[session].state == LLP_STATE_ESTABLISHED) {
		return_value = send_datagram(session, data, length);
	} else {
		liblog_error(LAYER_LINK, "the session is not established.");
		return_value = LLP_ERROR;
	}
	llp_unlock_session(session);
	
	return return_value;
}
/******************************************************************************/
int llp_hunt_valid(int session) {
	struct timeval time;
	struct timezone timezone;
	int return_value;
	long diff;
	
	gettimeofday(&time, &timezone);
	return_value = LLP_OK;
	
	llp_lock_session(session);
	diff = time.tv_sec - llp_sessions[session].hunt_time;
	if (diff > (LLP_T_TIMEOUT / LLP_TIME_TICKS_PER_SECOND)) {
		return_value = LLP_ERROR;;
	}
	llp_unlock_session(session);
	
	return return_value;
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int send_data(int session, u_char *data, int length) {
	int offset;
	int packet_length;
	int content_length;
	int mac_length;
	int return_value;
	u_char *mac;
	u_char *padding;
	u_char *packet;
	u_char *content;
	u_char *plain_content;
	u_short padding_length;

	liblog_debug(LAYER_LINK, "sending data by session %d.", session);
	
	if (llp_sessions[session].encrypted == LLP_SESSION_NOT_ENCRYPTED) {
		padding_length = 0;
	} else {
		if (length > LIBFREEDOM_FTU + sizeof(u_char)) {
			liblog_error(LAYER_LINK, 
					"can't send packet with more than FTU bytes: (%d>FTU)", 
					length);
			return LLP_ERROR;
		}
		/* Computing padding length. */
		padding_length = LLP_MIN_PADDING_LENGTH + sizeof(u_char) 
				+ LIBFREEDOM_FTU + sizeof(u_short);
		if (padding_length % llp_sessions[session].cipher->block_size != 0) {
			padding_length = padding_length 
					+ llp_sessions[session].cipher->block_size
					- (padding_length%llp_sessions[session].cipher->block_size);	
		}
		/* The type of the packet is already in data. */
		padding_length = padding_length - length - sizeof(u_short) ;
	}
	
	/* Determining the MAC length. */
	mac_length = llp_sessions[session].mac->length;
	
	/* Determining content length. */
	content_length = padding_length + length + sizeof(u_short);
	
	/* Determining the packet_size. */
	packet_length = 2*sizeof(u_char) + content_length + mac_length;

	liblog_debug(LAYER_LINK, "padding will be %d bytes long and packet will be "
			"%d bytes long.", padding_length, packet_length);

	/* Allocating buffers. */
	packet = (u_char*)malloc(packet_length);
	padding = (u_char*)malloc(padding_length);
	plain_content = (u_char*)malloc(content_length);
	mac = (u_char*)malloc(mac_length);
	
	if (packet == NULL || plain_content == NULL || mac == NULL ||
			padding == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	/* Generating padding. */
	if (util_rand_bytes(padding, padding_length) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating padding.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	/* Constructing content. */
	offset = 0;
	util_rand_bytes(padding, padding_length);
	util_write_bytes (plain_content, &offset, padding, padding_length);
	util_write_bytes (plain_content, &offset, data, length);
	util_write_uint16(plain_content, &offset, padding_length);
	
	/* Generating MAC of the plaintext content. */
	llp_sessions[session].mac->function(mac, plain_content,
			llp_sessions[session].mac_out_key, content_length);
	
	/* Constructing LLP_DATA packet. */
	UTIL_WRITE_START(packet)
	UTIL_WRITE_BYTE (LLP_DATA)
	UTIL_WRITE_BYTE (llp_sessions[session].foreign_session)

	/* Placing encrypted content in packet. */
	content = &packet[UTIL_WRITE_END]; 	/* Address to content be placed. */
	UTIL_WRITE_SEEK(content_length)		/* Skipping the content field. */

	/* Writing MAC on packet. */
	UTIL_WRITE_BYTES (mac, mac_length)
	
	/* Encrypting content */
	llp_sessions[session].cipher->function(content, plain_content, 
			llp_sessions[session].cipher_out_key,
			llp_sessions[session].cipher_out_iv, content_length,
			UTIL_WAY_ENCRYPTION);
			
	return_value = LLP_OK;
	
	/* Sending packet. */
	llp_sessions[session].silence = 0;
	llp_sessions[session].packets_sent++;
	if (llp_send_session_packet(session, packet, offset) == LLP_ERROR) {
		liblog_debug(LAYER_LINK, "error sending packet.");
		return_value = LLP_ERROR;
	}
	
	liblog_debug(LAYER_LINK, "packet sent.");

return_label:
	
	free(packet);
	free(plain_content);
	free(mac);
	free(padding);
	return return_value;
}
/******************************************************************************/
int send_datagram(int session, u_char *datagram, int length) {
	u_char *packet;
	
	liblog_debug(LAYER_LINK, "sending packet LLP_DATAGRAM.");

	packet = (u_char *)malloc(sizeof(u_char) + length);
	if (packet == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return LLP_ERROR;
	}

	/* Constructing packet. */
	UTIL_WRITE_START(packet)
	UTIL_WRITE_BYTE (LLP_DATAGRAM);
	UTIL_WRITE_BYTES(datagram, length);

	/* Sending packet. */
	if (send_data(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		free(packet);
		liblog_error(LAYER_LINK, "error sending packet.");
		return LLP_ERROR;
	}

	free(packet);

	return LLP_OK;	
	
}
/******************************************************************************/
int send_close(int session, u_char type) {
	int hash_length;
	u_char *packet;
	
	liblog_debug(LAYER_LINK, "sending packet LLP_CLOSE, with type %d.", type);

	hash_length = llp_sessions[session].hash->length;
	packet = (u_char *)malloc(sizeof(u_char) + hash_length);
	if (packet == NULL) {
		free(packet);
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return LLP_ERROR;
	}
	
	/* Constructing packet. */
	UTIL_WRITE_START(packet)
	UTIL_WRITE_BYTE (type);
	UTIL_WRITE_BYTES(llp_sessions[session].verifier, hash_length);
	
	/* Sending packet. */
	if (send_data(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		free(packet);
		liblog_error(LAYER_LINK, "error sending packet.");
		return LLP_ERROR;
	}

	free(packet);

	return LLP_OK;
}
/******************************************************************************/
int send_close_ok(int session) {
	return send_close(session, LLP_CLOSE_OK);
}
/******************************************************************************/
int send_close_request(int session) {
	return send_close(session, LLP_CLOSE_REQUEST);
}
/******************************************************************************/
int send_node_hunt(int session) {
	u_char packet[sizeof(u_char)];
	
	liblog_debug(LAYER_LINK, "sending packet LLP_NODE_HUNT.");

	/* Constructing packet. */
	UTIL_WRITE_START(packet)
	UTIL_WRITE_BYTE (LLP_NODE_HUNT);
	liblog_debug(LAYER_LINK, "packet constructed.");

	/* Sending packet. */
	if (send_data(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error sending packet.");
		return LLP_ERROR;
	}

	return LLP_OK;	
}
/******************************************************************************/
int send_hunt_result(int session, struct sockaddr_in *addresses, int number) {
	int i;
	u_char packet[LLP_HUNT_RESULT_MAX_LENGTH];
	
	liblog_debug(LAYER_LINK, "sending packet LLP_HUNT_RESULT.");

	/* Constructing packet. */
	UTIL_WRITE_START(packet);
	UTIL_WRITE_BYTE(LLP_HUNT_RESULT);
	UTIL_WRITE_BYTE(number);
	for (i = 0; i < number; i++) {
		UTIL_WRITE_BYTE(LLP_ADDRESS_INET);
		UTIL_WRITE_BYTES((u_char *)&addresses[i].sin_addr,
				sizeof(struct in_addr));
		/* We can use write_bytes beacuse sin_port is already stored on
		 * Network Byte Order. */
		UTIL_WRITE_UINT16(ntohs(addresses[i].sin_port));
	}

	/* Sending packet. */
	if (send_data(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error sending packet.");
		return LLP_ERROR;
	}

	return LLP_OK;
}
/******************************************************************************/
int send_keep_alive(int session) {
	u_char packet[sizeof(u_char)];
	
	liblog_debug(LAYER_LINK, "sending packet LLP_KEEP_ALIVE.");

	/* Constructing packet. */
	UTIL_WRITE_START(packet);
	UTIL_WRITE_BYTE(LLP_KEEP_ALIVE);

	/* Sending packet. */
	if (send_data(session, packet, UTIL_WRITE_END) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error sending packet.");
		return LLP_ERROR;
	}

	return LLP_OK;	
}
/******************************************************************************/
int handle_encrypted_content(u_char *encrypted, int length,
		u_char *mac, int session) {
	int offset;
	int return_value;
	u_char *plain_content;
	u_char *real_mac;
	llp_data_p packet;
	
	plain_content = (u_char*)malloc(length);
	real_mac = (u_char *)malloc(llp_sessions[session].mac->length);
	if (plain_content == NULL || real_mac == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return_value = LLP_ERROR;
		goto return_label;
	}

	/* Decrypting content. */
	llp_sessions[session].cipher->function(plain_content, encrypted, 
			llp_sessions[session].cipher_in_key,
			llp_sessions[session].cipher_in_iv, length, UTIL_WAY_DECRYPTION);
			
	/* Read the data after decryption. */
	offset = length - sizeof(u_short);
	util_read_uint16(&packet.padding_length, &offset, plain_content);

	llp_sessions[session].mac->function(real_mac, plain_content,
			llp_sessions[session].mac_in_key, length);

	if (memcmp(mac, real_mac, llp_sessions[session].mac->length) != 0) {
		/* MAC mismatch, drop packet. */
		liblog_error(LAYER_LINK, "MAC mismatch. packet dropped.");
		return_value = LLP_ERROR;
		goto return_label;
	}
	
	liblog_debug(LAYER_LINK, "MAC is correct.");
	
	return_value = handle_content(&plain_content[packet.padding_length],
			length - packet.padding_length - sizeof(u_short), session);
			
return_label:
	
	free(plain_content);
	free(real_mac);
	
	return return_value;
}
/******************************************************************************/
int handle_content(u_char *content,	int length, int session) {
	llp_data_p packet;

	/* Reading data content. */
	UTIL_READ_START(content, length, LLP_OK, LLP_ERROR)
	UTIL_READ_BYTE(packet.content_type)

	/* handle data type */
	switch (packet.content_type) {
		case LLP_DATAGRAM:
			liblog_debug(LAYER_LINK, "LLP_DATAGRAM received.");
			return handle_datagram(&content[1], length-1, session);
		case LLP_CLOSE_REQUEST:
			liblog_debug(LAYER_LINK, "LLP_CLOSE_REQUEST received.");
			return handle_close_request(content, length, session);
		case LLP_CLOSE_OK:
			liblog_debug(LAYER_LINK, "LLP_CLOSE_OK received.");
			return handle_close_ok(content, length, session);
		case LLP_NODE_HUNT:
			liblog_debug(LAYER_LINK, "LLP_NODE_HUNT received.");
			return handle_node_hunt(content, length, session);
		case LLP_HUNT_RESULT:
			liblog_debug(LAYER_LINK, "LLP_HUNT_RESULT received.");
			return handle_hunt_result(content, length, session);
		case LLP_KEEP_ALIVE:
			liblog_debug(LAYER_LINK, "LLP_KEEP_ALIVE received.");
			return handle_keep_alive(content, length, session);
		default:
			liblog_error(LAYER_LINK, "unknown type, packet dropped.");
			return LLP_ERROR;
	}
	
	UTIL_READ_END
}
/******************************************************************************/
int handle_datagram(u_char *content, int length, int session) {
	return llp_enqueue_datagram(session, content, length);
}
/******************************************************************************/
int handle_closing(u_char *content, int length, int session) {
	llp_data_p packet;
	int hash_length;
	
	packet.llp_close_request.verifier = (u_char *)
			malloc(llp_sessions[session].hash->length);
	if (packet.llp_close_request.verifier == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));	
		return LLP_ERROR;
	}
	
	hash_length = llp_sessions[session].hash->length;

	/* Reading packet. */
	UTIL_READ_START(content, length, LLP_OK, LLP_ERROR);
	UTIL_READ_BYTE(packet.content_type)
	UTIL_READ_BYTES(packet.llp_close_request.verifier, hash_length)

	if (memcmp(packet.llp_close_request.verifier, llp_sessions[session].verifier,
			hash_length) != 0) {
		/* Dropping packet. */
		free(packet.llp_close_request.verifier);
		liblog_error(LAYER_LINK, "verifier mismatch, packet dropped.");
		return LLP_ERROR;
	}
	
	free(packet.llp_close_request.verifier);
	
	UTIL_READ_END
}
/******************************************************************************/	
int handle_close_request(u_char *content, int length, int session) {
	
	if (handle_closing(content, length, session) == LLP_ERROR) {
		return LLP_ERROR;
	}
	
	/* If the session is already on TIME_WAIT state, the timeout is already
	 * counting. */
	if (llp_sessions[session].state != LLP_STATE_TIME_WAIT) {
		llp_sessions[session].state = LLP_STATE_TIME_WAIT;
		llp_sessions[session].timeout = LLP_T_TIMEOUT;
		llp_set_node_inactive(session);
	}

	return send_close_ok(session);
}
/******************************************************************************/
int handle_close_ok(u_char *content, int length, int session) {

	if (handle_closing(content, length, session) == LLP_ERROR) {
		return LLP_ERROR;
	}
	
	llp_close_session(session);
	
	return LLP_OK;
}
/******************************************************************************/
int handle_node_hunt(u_char *content, int length, int session) {
	struct sockaddr_in *addresses;
	int return_value;
	int capacity;
	u_char n;
	
	capacity = LIBFREEDOM_FTU / LLP_ADDRESS_INET_LENGTH;
	
	if (util_rand_bytes(&n, sizeof(u_char)) == LLP_ERROR ) {
		liblog_error(LAYER_LINK, "error generating node hunt result count.");
		return LLP_ERROR;
	}

	/* Computing number of nodes. */
	n = (int)((float)n)*((float)((float)capacity/MAX_CHAR));
	n = (n == 0 ? 1 : n);

	addresses = (struct sockaddr_in *)malloc(n * sizeof(struct sockaddr_in));
	if (addresses == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));	
		return LLP_ERROR;
	}
	
	/* Collecting nodes to be sent. */
	n = llp_get_nodes_from_cache(n, addresses);

	return_value = LLP_OK;
	
	if (send_hunt_result(session, addresses, n) == LLP_ERROR) {
		return_value = LLP_ERROR;
	} else {
		liblog_debug(LAYER_LINK, "packet LLP_HUNT_RESULT sent.");
	}
	
	free(addresses);
	return return_value;
}
/******************************************************************************/
int handle_hunt_result(u_char *content, int length, int session) {
	int i;
	struct sockaddr_in address;
	llp_data_p packet;
	
	if (llp_hunt_valid(session) == LLP_OK) {
		liblog_error(LAYER_LINK, "packet LLP_HUNT_RESULT timed out.");
		return LLP_ERROR;
	}
	
	/* Reading packet. */
	if (parse_hunt_result(&packet, content, length)	== LLP_ERROR) {
		liblog_debug(LAYER_LINK, "packet format corrupted.");	
		return LLP_ERROR;
	} 
	
	for (i = 0; i < packet.llp_hunt_result.size; i++) {
		address.sin_family = AF_INET;
		memcpy(&address.sin_addr, &packet.llp_hunt_result.list[i].address,
				sizeof(struct in_addr));
		address.sin_port = htons(packet.llp_hunt_result.list[i].port);
		llp_add_node_to_cache(&address);
	}
	
	free(packet.llp_hunt_result.list);
	
	return LLP_OK;
}
/******************************************************************************/
int handle_keep_alive(u_char *content, int length, int session) {
	llp_sessions[session].timeout = LLP_T_TIMEOUT;
	return LLP_OK;
}
/******************************************************************************/
int parse_hunt_result(llp_data_p *packet, u_char *data,	int length) {
	int i;
	int n;

	UTIL_READ_START(data, length, LLP_OK, LLP_ERROR)
	UTIL_READ_BYTE(packet->content_type)
	UTIL_READ_BYTE(packet->llp_hunt_result.size);
	
	n = packet->llp_hunt_result.size;
	
	packet->llp_hunt_result.list = (llp_address_t *)
			malloc(n * sizeof(llp_address_t));
	if (packet->llp_hunt_result.list == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return LLP_ERROR;
	}
	for (i = 0; i < n; i++) {
		UTIL_READ_BYTE(packet->llp_hunt_result.list[i].address_type)
		UTIL_READ_BYTES((u_char *)&packet->llp_hunt_result.list[i].address,
				sizeof(u_int))
		UTIL_READ_UINT16(packet->llp_hunt_result.list[i].port);
	}
	UTIL_READ_END
}
/******************************************************************************/
