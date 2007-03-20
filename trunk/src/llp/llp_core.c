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
 * @file llp_core.c Core functionality implementation of LLP module.
 * @ingroup llp
 */
 
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <pthread.h>

#include <libfreedom/layer_link.h>
#include <libfreedom/liblog.h>
#include <libfreedom/layers.h>

#include "llp.h"
#include "llp_config.h"
#include "llp_sessions.h"
#include "llp_nodes.h"
#include "llp_handshake.h"
#include "llp_data.h"
#include "llp_socket.h"
#include "llp_threads.h"
#include "llp_info.h"
#include "llp_queue.h"
 
/*============================================================================*/
/* Private data definitions.                                                   */
/*============================================================================*/

/*
 * Object that represents the interface of the link module.
 */
static layer_link_t interface;

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

layer_link_t *link_get_interface() {
	interface.link_connect_to = llp_connect_to;
	interface.link_connect_any = llp_connect_any;
	interface.link_register_connect = llp_register_connect;
	interface.link_unregister_connect = llp_unregister_connect;
	interface.link_register_close = llp_register_close;
	interface.link_unregister_close = llp_unregister_close;
	interface.link_read = llp_read;
	interface.link_write = llp_write;
	interface.link_disconnect = llp_disconnect;
	interface.link_get_last_error = llp_get_last_error;
	return &interface;
}
/******************************************************************************/
int link_initialize(char *config_file) {
	
	if (llp_configure(config_file) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error initializing llp.");
		return LINK_ERROR;
	}

	if (llp_create_socket(llp_get_port()) == LLP_ERROR) {
		return LINK_ERROR;	
	}

	if (llp_sessions_initialize() == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error initializing sessions.");
		return LINK_ERROR;
	}

	if (llp_nodes_initialize() == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error initializing nodes.");
		return LINK_ERROR;
	}
	
	if (llp_info_initialize() == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error initializing nodes.");
		return LINK_ERROR;
	}
	
	if (llp_queue_initialize() == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error initializing queue.");
		return LINK_ERROR;
	}
	
	if (llp_create_threads() == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error creating threads.");
		return LINK_ERROR;
	}
	
	liblog_debug(LAYER_LINK, "llp module initialized.");
	
	return LINK_OK;
}
/******************************************************************************/
void link_finalize() {
	
	llp_close_socket();	
	
	llp_destroy_threads();
	llp_queue_finalize();
	llp_sessions_finalize();
	llp_nodes_finalize();
	llp_info_finalize();
	llp_unconfigure();
	
	liblog_debug(LAYER_LINK, "llp module finalized.");
}
/******************************************************************************/
