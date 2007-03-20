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
 * @file net_stub.c Stub for the net module interface.
 * @ingroup net_stub
 */

#include <stdio.h>

#include <libfreedom/layer_link.h>
#include <libfreedom/layer_net.h>
#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>

/*============================================================================*/
/* Public data definitions.                                                   */
/*============================================================================*/

layer_link_t *layer_link;

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

static layer_net_t layer_net = {
	NULL, NULL, NULL
};

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

layer_net_t *net_get_interface() {
	liblog_debug(LAYER_NET, "layer_net_t structure returned.");
	return &layer_net;
}
/******************************************************************************/
int net_initialize(char *config_name, layer_link_t *layer_link_param) {
	layer_link = layer_link_param;
	liblog_info(LAYER_NET, "layer net initialized.");
	return NET_OK;
}
/******************************************************************************/
void net_finalize() {
	liblog_info(LAYER_NET, "layer net finalized.");
}
/******************************************************************************/
