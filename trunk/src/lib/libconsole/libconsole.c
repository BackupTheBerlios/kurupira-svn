/*
 * Copyright (C) 2006-07 The Kurupira Project
 * 
 * Kurupira is the legal property of its developers, whose names are not listed
 * here. Please refer to the COPYRIGHT file.
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
 * @file libconsole.c
 * 
 * Library used to communicate with the daemon console module.
 *
 * @version $Header$
 * @ingroup libconsole
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pwd.h>

#include "libconsole.h"

#include "kurud/kurud_console.h"

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/*
 * Establishes a new connection to the socket file of the daemon.
 * 
 * @param[out] socket	- the socket returned
 * @return LIBCONSOLE_OK if no error occurs, LIBCONSOLE_ERROR otherwise.
 */
static int console_connect(int *socket);

/*
 * Establishes a new connection to the UDS file of the deamon.
 * 
 * @param id - the id of the UDS to connect.
 * @return the socket connected. If any error occurs, -1 is returned.
 */
static int try_console_connect(uid_t id);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int libconsole_load_commands(command_list_t *console_commands, int layer_id)  {
	int socket;
	int command_id;
	int t;
	int sizeof_commands;
	char ack;

	/* Connect the the deamon console UDS file. */	
	socket = console_connect();
	if (socket == CONNECT_ERROR) {
		return LIBCONSOLE_ERROR;	
	}

	/* Send the layer_id. */
    if (send(socket, &layer_id, sizeof(layer_id), 0) == -1) {
        perror("send");
	    close(socket);
		return LIBCONSOLE_ERROR;	
    }

	/* Send the FREEDOMD_COMMAND_LIST_REQUEST, requesting the command list. */
	command_id = FREEDOMD_COMMAND_LIST_REQUEST;
    if (send(socket, &command_id, sizeof(command_id), 0) == -1) {
        perror("send");
	    close(socket);
		return LIBCONSOLE_ERROR;	
    }
	
	/* Receive the size of the command list. */
    if ((t=recv(socket, &sizeof_commands, sizeof(sizeof_commands), 0)) 
    		!= sizeof(sizeof_commands)) {
        if (t < 0) {
        	perror("recv");
        } else {
       		fprintf(stderr, "couldn't load commands.\n");
        }
	    close(socket);
        return LIBCONSOLE_ERROR;
    }
    
	/* Receive the command list from the server. */
    console_commands->list = (command_t *)malloc(sizeof_commands);
    if ((t=recv(socket, console_commands->list, sizeof_commands, 0)) 
    		!= sizeof_commands) {
        if (t < 0) {
        	perror("recv");
        } else {
       		fprintf(stderr, "couldn't load commands.\n");
        }
	    close(socket);
        return LIBCONSOLE_ERROR;
    }

	/* Close the connection. */
	send(socket, &ack, sizeof(ack), 0);
    close(socket);
    
    /* Determine the size of the commands list. */
    console_commands->size = sizeof_commands/sizeof(command_t);
    
    return LIBCONSOLE_OK;
}
/******************************************************************************/
int libconsole_send_command(int layer_id, int command_id, char *args) {
    char msg[101];
	unsigned char args_len;
	int aux;
	int socket;
	int t;
	int received_ok = 0;
	char ack;
	int msg_length;
	int readed_bytes;
	
	/* Connect the the deamon console UDS file. */	
	socket = console_connect();
	if (socket == CONNECT_ERROR) {
		return LIBCONSOLE_ERROR;	
	}

	/* Request the execution at the layer_id. */
    if (send(socket, &layer_id, sizeof(layer_id), 0) == -1) {
	    close(socket);
		return LIBCONSOLE_ERROR;	
    }

	/* Request the execution of the command_id. */
    if (send(socket, &command_id, sizeof(command_id), 0) == -1) {
	    close(socket);
		return LIBCONSOLE_ERROR;	
    }
    
	/* Send the size of arguments. The maximum size of arguments is 0xFF=255. */
    aux = strlen(args);
    args_len = (aux>0xFF?0xFF:aux);
    if (send(socket, &args_len, sizeof(args_len), 0) == -1) {
	    close(socket);
		return LIBCONSOLE_ERROR;	
    }
    
	/* Send the arguments string. */
    if (send(socket, args, args_len, 0) == -1) {
	    close(socket);
		return LIBCONSOLE_ERROR;	
    }    
    
	/* Receives the size of the returned message. */
    if ((t=recv(socket, &msg_length, sizeof(msg_length), 0)) 
    		!= sizeof(msg_length)) {
        if (t < 0) {
        	perror("recv");
        } else {
       		fprintf(stderr, "couldn't get returned data.\n");
        }
	    close(socket);
        return LIBCONSOLE_ERROR;
    }

  	/* Receive all data from server until the socket be closed.
	 * All data received is echoed into the stdout. */
	readed_bytes = 0;
	while (readed_bytes < msg_length) {
	    if ((t=recv(socket, msg, sizeof(msg)-1, 0)) > 0) {
	        msg[t] = '\0';
	        printf("%s", msg);
	        received_ok = 1;
	        readed_bytes += t;
	    } else {
	        if (t < 0) {
			    close(socket);
				return LIBCONSOLE_ERROR;	
	        }
	        break;
	    }
	}
	if (received_ok) {
		printf("\n");
	}

	/* Close the connection */
	send(socket, &ack, sizeof(ack), 0);
    close(socket);

	/* Return LIBCONSOLE_OK if successful execution. 
	 * LIBCONSOLE_COMMAND_ERROR otherwise. */
    return (received_ok ? LIBCONSOLE_OK : LIBCONSOLE_COMMAND_ERROR);
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

int console_connect() {
	int socket = CONNECT_ERROR;
	
	/* If the daemon_uid is already set, we return a new socket to it.
	 * If not, we will try to connect to the daemon of the following users,
	 * in order:
	 * 		1. Current User
	 * 		2. Freedomd User
	 * 		3. Root User
	 * If any of these users aren't running a daemon, we return an error. */
	if (daemon_uid == UID_NOT_SET) {
		
		/* Try to connect to the UDS daemon with the current uid. */
		daemon_uid = getuid();
		socket = try_console_connect(daemon_uid);
		if (socket != CONNECT_ERROR) {
			return socket;	
		}

		/* Try to connect to the UDS daemon with the LIBFREEDOM_UID. */
		daemon_uid = getpwnam(LIBFREEDOM_USER_NAME)->pw_uid;
		socket = try_console_connect(daemon_uid);
		if (socket != CONNECT_ERROR) {
			return socket;	
		}

		/* Try to connect to the UDS daemon with the ROOT_UID. */
		daemon_uid = ROOT_UID;
		socket = try_console_connect(daemon_uid);

		return socket;
	} else {
		return try_console_connect(daemon_uid);
	}
}
/******************************************************************************/
int try_console_connect() {
    int s, len;
    struct sockaddr_un remote;
    char filename[100];
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return CONNECT_ERROR;
    }

	snprintf(filename, sizeof(filename), UDS_NAME_FORMAT, (int)id);

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, filename);
    len = strlen(remote.sun_path) + 1 + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        return CONNECT_ERROR;
    }

    return s;
}
/******************************************************************************/
