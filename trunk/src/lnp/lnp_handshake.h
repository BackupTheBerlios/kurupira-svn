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
 * @file lnp_handshake.h Functions used to establish a new connection.
 * @ingroup lnp
 */
 
#ifndef _LNP_HANDSHAKE_H_
#define _LNP_HANDSHAKE_H_

#include <sys/types.h>
#include <netinet/in.h>

#include "lnp_packets.h"

/**
 * Timeout used to give up a handshake attempt.
 */
#define LNP_T_HANDSHAKE		(30*LNP_TIME_TICKS_PER_SECOND)

/**
 * Handles the event of receiving a LNP_PUBLIC_KEY_REQUEST packet.
 * 
 * @param packet packet data.
 * @param content_length length in bytes of packet->content.
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_handle_public_key_request(lnp_packet_p *packet, int content_length);
		
/**
 * Handles the event of receiving a LLP_PUBLIC_KEY_RESPONSE packet.
 * 
 * @param packet packet data.
 * @param content_length length in bytes of packet->content.
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_handle_public_key_response(lnp_packet_p *packet, int packet_length);

/**
 * Handles the event of receiving a LNP_KEY_EXCHANGE packet.
 * 
 * @param packet packet data.
 * @param content_length length in bytes of packet->content.
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_handle_key_exchange(lnp_packet_p *packet, int content_length);

/**
 * Handles the event of receiving a LNP_KEY_EXCHANGE_OK packet.
 * 
 * @param packet packet data.
 * @param content_length length in bytes of packet->content.
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_handle_key_exchange_ok(lnp_packet_p *packet, int content_length);

/**
 * Connects to the given host and negotiates session keys with it.
 * 
 * @param id destination ID address.
 * @return NET_OK if no errors occurred, NET_ERROR otherwise.
 */
int lnp_connect(net_id_t id);

#endif /* !_LNP_HANDSHAKE_H_ */
