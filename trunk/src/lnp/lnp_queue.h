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
 * @file lnp_queue.h Hedaers of functions used by the LNP modules to provide the
 * 		datagrams received to the upper layers.
 * @ingroup lnp
 */

#ifndef _LNP_QUEUE_H_
#define _LNP_QUEUE_H_

/**
 * Initializes the queue, allocating needed memory.
 */
int lnp_queue_initialize();

/**
 * Finalizes the queue managed by LNP to store received datagrams, performing
 * cleanup.
 */
void lnp_queue_finalize();

/**
 * Enqueues a datagram received by the LNP module so it can be retrieved later 
 * by the upper layer.
 * 
 * @param from source ID address.
 * @param data datagram received.
 * @param length length in bytes of datagram.
 * @param protocol TODO: comentar
 * @returns LNP_OK if no errors occurred, LNP_ERROR otherwise.
 */
int lnp_enqueue_datagram(net_id_t from, u_char *datagram, int length, 
		u_char protocol);

/**
 * Dequeues a datagram received by the LLP module. The datagram vector must be
 * pre-allocated with size specified in max.
 * 
 * @param from source ID address that the datagram arrived through.
 * @param datagram array that will receive the data.
 * @param max size of array (max number of bytes that can be copied).
 * @param protocol TODO: comentar
 * @return the length in bytes of the datagram received, or LNP_ERROR if errors
 * occurred during dequeueing.
 */
int lnp_dequeue_datagram(net_id_t from, u_char *datagram, int max,
		u_char protocol);

/**
 * Dequeues a datagram received by the LNP module. The datagram vector must be
 * pre-allocated with size specified in max. If the queue don't have any
 * element, an error is returned.
 * 
 * @param from source ID address that the datagram arrived through.
 * @param datagram array that will receive the data.
 * @param max size of array (max number of bytes that can be copied).
 * @param protocol TODO: comentar
 * @return the length in bytes of the datagram received, or LLP_ERROR if errors
 * occurred during dequeueing.
 */
int lnp_try_dequeue_datagram(net_id_t from, u_char *datagram, int max,
		u_char protocol);

#endif /* !_LLP_QUEUE_H_ */
