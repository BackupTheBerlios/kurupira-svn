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
 * @file lnp_data.h Headers of functions used to manipulate LNP_DATA packets.
 * @ingroup lnp
 */
 
#ifndef _LNP_DATA_H_
#define _LNP_DATA_H_

#include <sys/types.h>

#include "lnp_packets.h"

/**
 * Handle a received LLP_DATA packet.
 * 
 * @param packet_data packet data.
 * @param packet_length packet length in bytes.
 * @return LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int lnp_handle_data(lnp_packet_p *packet, int packet_length);

/**
 * Reads data received by LNP module.
 * 
 * @param from source ID address of the received datagram.
 * @param data array that will receive data.
 * @param max max number of bytes that can be read (i.e., the size of data).
 * @param protocol
 * @return number in bytes of the datagram read, LNP_ERROR otherwise.
 */
int lnp_read(net_id_t from, u_char *data, int max, u_char protocol);

/**
 * Sends generic data by the given session.
 * 
 * @param id_to destination ID address of the sent datagram.
 * @param data data to be sent.
 * @param length length of data in bytes.
 * @param protocol protocol sending this data
 * @return LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_write(net_id_t id_to, u_char *data, int length, u_char protocol);

/**
 * Remove all enqueued messages.
 * 
 * @param protocol - the protocol to flush messages (LUP or LTP).
 * @return the number of messages flushed.
 */
int lnp_flush(u_char protocol);

#endif /* !_LLP_DATA_H_ */
