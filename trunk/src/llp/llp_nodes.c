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
 * @file llp_nodes.c Implementations of routines used to manipulate tables of
 * 		active connected hosts and nodes cache.
 * @ingroup llp
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libfreedom/liblog.h>
#include <util/util_crypto.h>

#include "llp.h"
#include "llp_sessions.h"
#include "llp_data.h"
#include "llp_config.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Condition that two nodes have the same address.
 */
#define SAME_NODE_ADDRESS(NODE1, NODE2)						 				\
	((*(int *)&((NODE1)->sin_addr)) ==								\
	(*(int *)&((NODE2)->sin_addr))									\
	&& ((NODE1)->sin_port == (NODE2)->sin_port))

/*
 * Defines the minimal percentual of the cache that mus be filled with nodes.
 */
#define CACHE_MIN_PERCENT_FILL	(0.5)

/*
 * Max value of a unsigned int.
 */
#define MAX_INT			0xffffffff

/*
 * Codes used to represent node state.
 */
#define NODE_INACTIVE 	0
#define NODE_ACTIVE		1
#define NODE_CONNECTING	2

/*
 * Max size of a hostname found on a node file.
 */
#define HOSTNAME_MAX_LENGTH	256

/*
 * Max number of connected hosts.
 */
#define MAX_ACTIVE_NODES	LLP_MAX_SESSIONS

/**
 * Data type that represents the information associated with a node.
 */
typedef struct {
	int session;				/**< Session used to connect with this node. */
	int state;					/**< This node is active. */
	struct sockaddr_in address;	/**< Address of this node. */
} node_t;

/**
 * Data type that represents the list of known nodes.
 */
typedef struct {
	/** Index of the last active node. */
	int active;
	/** Indexes of the nodes in cache that are active. */
	int active_list[MAX_ACTIVE_NODES];
	/** Total size of the structure. */
	int cache_size;					
	/** Index of the last used cache slot. */
	int cached;
	/** List of stored nodes. */
	node_t *cache_list;					
} nodes_t;

/*
 * Array of known hosts.
 */
static nodes_t nodes;

/*
 * Mutexes used to access the nodes pool and connected hosts array,
 * respectively.
 */
static pthread_mutex_t nodes_mutex;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/*
 * Fills up the nodes cache with the contents of the given file.
 */
static int fill_cache(char *filename);

/*
 * Fills up a file with the information associated with the current nodes stored
 * on cache.
 */
static int fill_file(char *filename);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_nodes_initialize() {

	nodes.cache_size = llp_get_cache_size();
	
	/* Allocating memory and clearing nodes cache. */
	nodes.cache_list = (node_t *)malloc((MAX_ACTIVE_NODES + nodes.cache_size) *
			sizeof(node_t));
	if (nodes.cache_list == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return LLP_ERROR;
	}
	nodes.cached = 0;
	nodes.active = 0;
	
	/* Initializing mutexes. */
	if (pthread_mutex_init(&nodes_mutex, NULL) > 0) {
		liblog_error(LAYER_LINK, "error allocating nodes mutex: %s.",
				strerror(errno));
		return LLP_ERROR;
	}
	
	liblog_debug(LAYER_LINK, "mutex initialized.");
	
	/* Fill the cache. */
	if (fill_cache(llp_get_static_nodes_file()) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error getting nodes from static nodes file.");
	}
	if (fill_cache(llp_get_recent_nodes_file()) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error getting nodes from recent nodes file.");
	}
	if (nodes.cached == 0) {
		liblog_error(LAYER_LINK, "error filling nodes cache, cache empty.");
	}

	/* Clearing active hosts table. */
	memset(nodes.active_list, 0, sizeof(nodes.active_list));
	
	liblog_debug(LAYER_LINK, "nodes module initialized.");
	
	return LLP_OK;
}
/******************************************************************************/
void llp_nodes_finalize() {
	/* Writing file. */
	fill_file(llp_get_recent_nodes_file());
	
	/* Freeing memory allocated to hosts cache. */
	free(nodes.cache_list);
	
	/* Freeing mutexes. */
	pthread_mutex_destroy(&nodes_mutex);
	
	liblog_debug(LAYER_LINK, "mutex destroyed.");
	
	liblog_debug(LAYER_LINK, "nodes module finalized.");
}
/******************************************************************************/
int llp_get_session_by_address(struct sockaddr_in *address) {
	int i;
	int session;

	pthread_mutex_lock(&nodes_mutex);
	
	/* Searching node in active nodes. */
	for (i = 0; i < nodes.active; i++) {
		if (SAME_NODE_ADDRESS(&nodes.cache_list[nodes.active_list[i]].address,
				address)) {
			/* This node is connected. */
			session = nodes.cache_list[nodes.active_list[i]].session;
			liblog_debug(LAYER_LINK, "session %d found.", session);
			pthread_mutex_unlock(&nodes_mutex);
			return session;
		}
	}
	
	pthread_mutex_unlock(&nodes_mutex);

	/* There is no connection to this node. */
	return LLP_ERROR;
}
/******************************************************************************/
int llp_get_nodes_from_cache(int number, struct sockaddr_in *addresses) {
	unsigned int position;
	int i;
	
	if (number > nodes.cached) {
		number = nodes.cached;
	}
	if (number == 0) {
		return LLP_ERROR;	
	}

	if (util_rand_bytes(&position, sizeof(unsigned int)) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating random node index.");
		return LLP_ERROR;	
	}
	
	pthread_mutex_lock(&nodes_mutex);
	
	/* Reducing position magnitude. */
	position = (int)((float)(nodes.cached))* (((float)position)/MAX_INT);

	for (i = 0; i < number; i++) {
		memcpy(&addresses[i], &nodes.cache_list[position].address,
				sizeof(struct sockaddr_in));			
		position++;
		position %= (nodes.cached);
	}

	liblog_debug(LAYER_LINK, "random nodes got.");
	
	pthread_mutex_unlock(&nodes_mutex);
	
	return number;
}
/******************************************************************************/
int llp_add_node_to_cache(struct sockaddr_in *address) {
	int i;

	pthread_mutex_lock(&nodes_mutex);
	
	for (i = 0; i < nodes.cached; i++) {
		if (SAME_NODE_ADDRESS(&nodes.cache_list[i].address,
				address)) {
			/* Node is already cached. */
			/*liblog_error(LAYER_LINK, "node already on cache.");*/
			pthread_mutex_unlock(&nodes_mutex);
			return LLP_ERROR;
		}
	}
	if (nodes.cached < nodes.cache_size) {
		liblog_debug(LAYER_LINK, "node %s:%d added to cache.",
				inet_ntoa(address->sin_addr), ntohs(address->sin_port));
		memcpy(&nodes.cache_list[nodes.cached++].address, address,
				sizeof(struct sockaddr_in));
		nodes.cache_list[nodes.cached].state = NODE_INACTIVE;
	} else {
		liblog_debug(LAYER_LINK, "cache full.");
		for (i = 0; i < nodes.cached; i++) {
			if (nodes.cache_list[i].state == NODE_INACTIVE) {
				memcpy(&nodes.cache_list[i].address, address, 
						sizeof(struct sockaddr_in));
			}
		}
	}
	
	pthread_mutex_unlock(&nodes_mutex);
	
	/* Node is not present. */
	return LLP_OK;
}
/******************************************************************************/
int llp_set_node_active(struct sockaddr_in *address, int session) {
	int i;

	pthread_mutex_lock(&nodes_mutex);

	/* There's room for this node. */
	if (nodes.active < MAX_ACTIVE_NODES)  {
		for (i = 0; i < nodes.active; i++) {
			if (SAME_NODE_ADDRESS(
					&nodes.cache_list[nodes.active_list[i]].address, address)) {
				liblog_error(LAYER_LINK, "node already active.");
				pthread_mutex_unlock(&nodes_mutex);
				return LLP_OK;
			}
		}
		for (i = 0; i < nodes.cached; i++) {
			if (SAME_NODE_ADDRESS(&nodes.cache_list[i].address, address)) {
				nodes.active_list[nodes.active++] = i;
				nodes.cache_list[i].state = NODE_ACTIVE;
				nodes.cache_list[i].session = session;
				liblog_debug(LAYER_LINK, "node activated.");
				pthread_mutex_unlock(&nodes_mutex);
				return LLP_OK;
			}
		}
	}
	
	pthread_mutex_unlock(&nodes_mutex);

	liblog_error(LAYER_LINK, "node not found.");
	return LLP_ERROR;
}
/******************************************************************************/
int llp_set_node_connecting(struct sockaddr_in *address, int session) {
	int i;

	pthread_mutex_lock(&nodes_mutex);

	/* There's room for this node. */
	if (nodes.active < MAX_ACTIVE_NODES)  {
		for (i = 0; i < nodes.active; i++) {
			if (SAME_NODE_ADDRESS(
					&nodes.cache_list[nodes.active_list[i]].address, address)) {
				liblog_error(LAYER_LINK, "node already active.");
				pthread_mutex_unlock(&nodes_mutex);
				return LLP_OK;
			}
		}
		for (i = 0; i < nodes.cached; i++) {
			if (SAME_NODE_ADDRESS(&nodes.cache_list[i].address, address)) {
				nodes.active_list[nodes.active++] = i;
				nodes.cache_list[i].state = NODE_CONNECTING;
				nodes.cache_list[i].session = session;
				liblog_debug(LAYER_LINK, "node connecting.");
				pthread_mutex_unlock(&nodes_mutex);
				return LLP_OK;
			}
		}
	}
	
	pthread_mutex_unlock(&nodes_mutex);

	liblog_error(LAYER_LINK, "node not found.");
	return LLP_ERROR;
}
/******************************************************************************/
int llp_set_node_inactive(int session) {
	int i;
	
	pthread_mutex_lock(&nodes_mutex);

	/* Substituting node with the last active and freeing a slot. */
	for (i = 0; i < nodes.active; i++) {
		if (nodes.cache_list[nodes.active_list[i]].session == session) {
			nodes.active_list[i] = nodes.active_list[--nodes.active];
			nodes.cache_list[nodes.active_list[i]].state = NODE_INACTIVE;
			liblog_debug(LAYER_LINK, "node deactivated.");
			pthread_mutex_unlock(&nodes_mutex);
			return LLP_OK;
		}
	}

	pthread_mutex_unlock(&nodes_mutex);
	liblog_error(LAYER_LINK, "no active node found with this session.");
	return LLP_ERROR;
}
/******************************************************************************/
int llp_get_inactive_node(struct sockaddr_in *address) {
	unsigned int position = 0;
	int i;

	if (util_rand_bytes(&position, sizeof(unsigned int)) == LLP_ERROR) {
		liblog_error(LAYER_LINK, "error generating random node index.");
		return LLP_ERROR;	
	}

	pthread_mutex_lock(&nodes_mutex);

	/* Reducing position magnitude. */
	position = (int)((float)(nodes.cached)) * (((float)position)/MAX_INT);
	
	/* Looking for a node after position. */
	i = position;
	while (i < position) {
		if (nodes.cache_list[i].state == NODE_INACTIVE) {
			liblog_debug(LAYER_LINK, "inactive node found.");
			memcpy(address, &nodes.cache_list[i].address,
					sizeof(struct sockaddr_in));
			pthread_mutex_unlock(&nodes_mutex);			
			return LLP_OK;
		}
		i++;
		i %= (nodes.cached);
	}
	
	pthread_mutex_unlock(&nodes_mutex);
	
	return LLP_ERROR;
}
/******************************************************************************/
void llp_handle_nodes() {
	int i;
	int active = 0;
	int sessions[MAX_ACTIVE_NODES];
	
	/* Collecting active sessions. */
	if (pthread_mutex_trylock(&nodes_mutex) == 0) {
		if (nodes.cached < (int)(CACHE_MIN_PERCENT_FILL * nodes.cache_size)) {
			active = 0;
			for (i = 0; i < nodes.active; i++) {
				if (nodes.cache_list[nodes.active_list[i]].state ==	NODE_ACTIVE
						&& (llp_hunt_valid(i) == LLP_OK)) {
					sessions[active++] =
							nodes.cache_list[nodes.active_list[i]].session;
				}
			}
		}
		pthread_mutex_unlock(&nodes_mutex);
	
		/* The session numbers collected might be not active in sending time,
		 * but it's not a problem, because the function llp_hunt_for_nodes() 
		 * fails if a closed session number is received. The worst case is that
		 * an LLP_NODE_HUNT packet won't be sent. This adjustment was made to
		 * prevent deadlocks in the acquirement of the session lock inside the
		 * critical section protected by the nodes mutex. */
	
		/* Hunting for new nodes in active sessions. */
		for (i = 0; i < active; i++) {	
			llp_hunt_for_nodes(sessions[i]);
		}
	}
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int fill_cache(char *filename) {
	FILE *file;
	int i;
	int port;
	int error;
	int end;
	char hostname[HOSTNAME_MAX_LENGTH];
	struct addrinfo *result;
	struct addrinfo hints;
	
	file = fopen(filename, "r");
	if (file == NULL) {
		liblog_warn(LAYER_LINK, "error opening file %s: %s.", filename,
				strerror(errno));
		return LLP_ERROR;
	}
	
	/* Only IPv4 addresses supported. */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_INET;
	
	/* Reading hosts. */
	end = 0;
	for (i = nodes.cached; i < nodes.cache_size && !end; i++) {
		if (fscanf(file, "%255[^:]:%d\n", hostname, &port) == 2) {
			liblog_debug(LAYER_LINK, "node found: %s %d", hostname, port);
			error = getaddrinfo(hostname, NULL, &hints, &result);
			if (error) {
				liblog_debug(LAYER_LINK, "error in getaddrinfo: %s.",
						gai_strerror(error));
			} else {
				if (result->ai_addrlen == sizeof(struct sockaddr_in)) {
					((struct sockaddr_in *)result->ai_addr)->sin_port =
							htons(port);
					llp_add_node_to_cache(
							(struct sockaddr_in *)result->ai_addr);
				}
			}
			freeaddrinfo(result);
		} else {
			liblog_debug(LAYER_LINK, "end of file reached.");
			end = 1;
		}
	}

	fclose(file);
	
	return (i-1);
}
/******************************************************************************/
int fill_file(char *filename) {
	FILE *file;
	int i;
			
	liblog_debug(LAYER_LINK, "nodes on cache: %d.", nodes.cached);

	if (nodes.cached == 0) {
		liblog_warn(LAYER_LINK, "cache empty.");
		return LLP_OK;
	}

	file = fopen(filename, "w");
	if (file == NULL) {
		liblog_error(LAYER_LINK, "error creating file: %s", strerror(errno));
		return LLP_ERROR;
	}
	
	for (i = 0; i < nodes.cached; i++) {
		fprintf(file, "%s:%d\n",
				inet_ntoa(nodes.cache_list[i].address.sin_addr),
				ntohs(nodes.cache_list[i].address.sin_port));
	}
	
	fclose(file);

	return LLP_OK;
}
/******************************************************************************/
