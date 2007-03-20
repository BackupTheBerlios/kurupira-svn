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
 * @file llp_info.c Implementations of procedures used to manage layer info.
 * @ingroup llp
 */
 
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include <libfreedom/liblog.h>
#include <libfreedom/layers.h>

#include "llp_info.h"
#include "llp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/**
 * Data type that represents the information associated with the link layer.
 */
typedef struct {
	int active_sessions_counter;	/**< Number of active sessions. */
} llp_info_t;

/*
 * Object that stores the information associated with the link layer.
 */
static llp_info_t info;

/*
 * Lock used to access the llp info object.
 */
static pthread_mutex_t info_mutex;

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_info_initialize() {

	if (pthread_mutex_init(&info_mutex, NULL) > 0) {
		liblog_error(LAYER_LINK, "error allocating mutex: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	
	liblog_debug(LAYER_LINK, "mutex initialized.");
	
	info.active_sessions_counter = 0;
	
	return LLP_OK;
}
/******************************************************************************/
void llp_info_finalize() {

	pthread_mutex_destroy(&info_mutex);
	
	liblog_debug(LAYER_LINK, "mutex destroyed.");
}
/******************************************************************************/
int llp_get_active_sessions_counter() {
	int return_value;
	
	pthread_mutex_lock(&info_mutex);
	return_value = info.active_sessions_counter;
	pthread_mutex_unlock(&info_mutex);
	
	return return_value;
}
/******************************************************************************/
void llp_add_active_sessions_counter(int increment) {
	pthread_mutex_lock(&info_mutex);
	info.active_sessions_counter += increment;
	pthread_mutex_unlock(&info_mutex);
}
/******************************************************************************/
