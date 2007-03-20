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
 * @file lnp_core.c Core functionality implementation of LNP module.
 * @ingroup lnp
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

#include "lnp.h"
#include "lnp_id.h"
#include "lnp_link.h"
#include "lnp_queue.h"
#include "lnp_config.h"
#include "lnp_threads.h"
#include "lnp_routing_table.h"

/*============================================================================*/
/* Public data definitions.                                                   */
/*============================================================================*/

layer_link_t *link_interface;

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Object that represents the interface of this network module.
 */
static layer_net_t interface;

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

layer_net_t *net_get_interface() {
//	interface.net_write = lnp_read;
//	interface.net_read = lnp_write;
	return &interface;
}
/******************************************************************************/
void net_set_link_interface(layer_link_t *link_interface) {
	link_interface = link_interface;
}
/******************************************************************************/
layer_link_t *net_get_link_interface() {
	return link_interface;
}
/******************************************************************************/
int net_initialize(char *config_file, layer_link_t *layer_link) {
	
	link_interface = layer_link;
	
	if (lnp_configure(config_file) == LNP_ERROR) {
		liblog_error(LAYER_NET, "error initializing lnp.");
		return LINK_ERROR;
	}

	/*if (lnp_sessions_initialize() == LNP_ERROR) {
		liblog_error(LAYER_NET, "error initializing sessions.");
		return LINK_ERROR;
	}

	if (lnp_nodes_initialize() == LNP_ERROR) {
		liblog_error(LAYER_NET, "error initializing nodes.");
		return LINK_ERROR;
	}
	
	if (lnp_info_initialize() == LNP_ERROR) {
		liblog_error(LAYER_NET, "error initializing nodes.");
		return LINK_ERROR;
	}*/
	
	if (lnp_id_initialize() == LNP_ERROR) {
		liblog_error(LAYER_NET, "error loading key pair.");
		return LINK_ERROR;
	}

	if (lnp_queue_initialize() == LNP_ERROR) {
		liblog_error(LAYER_NET, "error initializing queue.");
		return LINK_ERROR;
	}
	
	if (lnp_routing_table_initialize() == LNP_ERROR) {
		liblog_error(LAYER_NET, "error initializing routing table.");
		return LINK_ERROR;
	}

	if (lnp_create_threads() == LNP_ERROR) {
		liblog_error(LAYER_NET, "error creating threads.");
		return LINK_ERROR;
	}
	
	link_interface->link_register_connect(lnp_link_connect_handler);
	link_interface->link_register_close(lnp_link_close_handler);
	
	liblog_debug(LAYER_NET, "lnp module initialized.");
	
	return LINK_OK;
}
/******************************************************************************/
void net_finalize() {
	
	lnp_destroy_threads();
	lnp_queue_finalize();
	//lnp_sessions_finalize();
	//lnp_nodes_finalize();
	//lnp_info_finalize();
	//lnp_unconfigure();
	
	liblog_debug(LAYER_NET, "lnp module finalized.");
}
/******************************************************************************/
