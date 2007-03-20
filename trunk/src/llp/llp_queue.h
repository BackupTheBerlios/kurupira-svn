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
 * @file llp_queue.h Hedaers of functions used by the LLP modules to provide the
 * 		datagrams received to the upper layers.
 * @ingroup llp
 */

#ifndef _LLP_QUEUE_H_
#define _LLP_QUEUE_H_

/**
 * Initializes the queue, allocating needed memory.
 */
int llp_queue_initialize();

/**
 * Finalizes the queue managed by LLP to store received datagrams, performing
 * cleanup.
 */
void llp_queue_finalize();

/**
 * Enqueues a datagram received by the LLP module so it can be retrieved later 
 * by the upper layer.
 * 
 * @param session session identifier.
 * @param datagram datagram received.
 * @param length length in bytes of datagram.
 * @returns LLP_OK if no errors occurred, LLP_ERROR otherwise.
 */
int llp_enqueue_datagram(int session, u_char *datagram, int length);

/**
 * Dequeues a datagram received by the LLP module. The datagram vector must be
 * pre-allocated with size specified in max.
 * 
 * @param session session that the datagram arrived through.
 * @param datagram array that will receive the data.
 * @param max size of array (max number of bytes that can be copied).
 * @return the length in bytes of the datagram received, or LLP_ERROR if errors
 * occurred during dequeueing.
 */
int llp_dequeue_datagram(int *session, u_char *datagram, int max);

/**
 * Dequeues a datagram received by the LLP module. The datagram vector must be
 * pre-allocated with size specified in max. If the queue don't have any
 * element, an error is returned.
 * 
 * @param session session that the datagram arrived through.
 * @param datagram array that will receive the data.
 * @param max size of array (max number of bytes that can be copied).
 * @return the length in bytes of the datagram received, or LLP_ERROR if errors
 * occurred during dequeueing.
 */
int llp_try_dequeue_datagram(int *session, u_char *datagram, int max);

#endif /* !_LLP_QUEUE_H_ */
