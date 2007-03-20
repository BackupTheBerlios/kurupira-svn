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
 * @file kurud_console.c
 * 
 * Execute commands requested by the libconsole library. This module delegates
 * the command execution to all the layers.
 * 
 * @version $Header$
 * @ingroup kurud
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

#include <liblog.h>
#include <liberror.h>
#include <kurupira/layer_console.h>
#include <kurupira/layers.h>

#include "kurud_console.h"
#include "kurud_config.h"
#include "kurud_err.h"
#include "kurud.h"

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/**
 * Maximum length of message returned to the console.
 */
#define COMMAND_RETURN_LENGTH 	1024

/**
 * Maximum length of a command's arguments.
 */
#define COMMAND_ARGS_LENGTH		256

/**
 * Number of pending connections.
 */
#define SOCKET_BACKLOG			4

/**
 * Permissions over the socket file.
 */
#define SOCKET_PERMISSIONS 		(S_IXGRP | S_IXOTH)

/**
 * Indicates that the UDS is closed.
 */
#define SOCKET_CLOSED 			(-1)

/**
 * Protocol identifier used to communicate with the clients.
 */
#define NO_PROTOCOL				0

/**
 * Descriptor for the thread that listens the socket.
 */
static pthread_t listen_thread;

/**
 * Socket descriptor.
 */
static int socket_descriptor = SOCKET_CLOSED;

/**
 * Start listening the UDS in a new thread.
 * 
 * @param[in] arg - not used(necessary for pthreads API)
 * @return Not used (necessary for pthreads API).
 */
static void *listen_socket(void *arg);

/**
 * Handles a new socket.
 * 
 * @param[in] arg - the socket descriptor
 * @return Not used (necessary for pthreads API).
 */
static void *handle_connection(void *arg);

/**
 * Handle request for a list of commands.
 * 
 * @param[in] socket    - the client socket descriptor
 * @param[in] layer     - the layer to request the command list
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int handle_command_list_request(int socket, int layer);

/**
 * Handles request for command execution.
 * 
 * @param[in] socket    - the client socket descriptor
 * @param[in] layer     - the layer to request the command execution
 * @param[in] command   - the command identifier
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int handle_execution_request(int socket, int layer, int command);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int kurud_console_init() {
	int len;
	int old_mask;
	int bind_return;
	struct sockaddr_un local;
	int code;

	code = KURUD_ERROR;

	/* Create socket file. */
	TRY((socket_descriptor = socket(AF_UNIX, SOCK_STREAM, NO_PROTOCOL)) != -1,
			ERROR(REASON_SOCKET_CREATE, strerror(errno)));

	liblog_debug(MODULE_DAEMON, "name of console socket: %s.",
			kurud_get_console_file);

	/* sockaddr_un structure setup. */
	local.sun_family = AF_UNIX;
	len = strlen(kurud_get_console_file());
	ASSERT(len < sizeof(local.sun_path), ERR(REASON_SOCKET_TOO_LONG));
	strncpy(local.sun_path, kurud_get_console_file(), len);

	/* Delete UDS file if it exists. */
	TRY(unlink(local.sun_path) != -1, ERROR(REASON_UNLINK, strerror(errno)));

	len = sizeof(local);

	/* Bind the UDS. */
	old_mask = umask(SOCKET_PERMISSIONS);
	bind_return = bind(socket_descriptor, (struct sockaddr *)&local, len);
	umask(old_mask);

	/* Check bind return. */
	ASSERT(bind_return != -1,
			ERROR(REASON_SOCKET_BIND, kurud_get_console_file()));

	/* Start listening at the socket. */
	TRY(listen(socket_descriptor, SOCKET_BACKLOG) != -1,
			ERROR(REASON_SOCKET_LISTEN, strerror(errno)));

	/* Thread to listen packets. */
	TRY(pthread_create(&listen_thread, NULL, listen_socket,
					(void *)socket_descriptor) == 0,
			ERROR(REASON_THREAD_CREATE, strerror(errno)));

	code = KURUD_OK;

	liblog_info(MODULE_DAEMON, "kurud console initialized.");

end:
	return code;
}

int kurud_console_wait() {
	int code;

	code = KURUD_ERROR;
	TRY(pthread_join(listen_thread, NULL) == 0,
			ERROR(REASON_THREAD_RUN, strerror(errno)));

	code = KURUD_OK;
end:
	return code;

}

int kurud_console_finish() {
	int code;

	code = KURUD_ERROR;

	/* Close and delete socket file if it exists. */
	if (socket_descriptor != SOCKET_CLOSED) {
		TRY(unlink(kurud_get_console_file()) != -1,
				ERROR(REASON_UNLINK, strerror(errno)));
		TRY(close(socket_descriptor) != -1,
				ERROR(REASON_SOCKET_CLOSE, strerror(errno)));
	}
	TRY(pthread_cancel(listen_thread) == 0,
			ERROR(REASON_THREAD_CANCEL, strerror(errno)));

	code = KURUD_OK;
end:
	liblog_info(MODULE_DAEMON, "kurud console finalized.");
	return code;
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

static void *listen_socket(void *arg) {
	socklen_t socklen; /* sockaddr size */
	int client; /* socket accepted at UDS */
	pthread_t child; /* thread processing socket */
	struct sockaddr remote; /* sockaddr structure for client socket */
	int code;

	code = KURUD_ERROR;

	while (1) {

		/* Obtain the client socket.. */
		socklen = sizeof(remote);
		client = accept(socket_descriptor, (struct sockaddr *)&remote,
				&socklen);
		ASSERT(client != -1, ERROR(REASON_SOCKET_ACCEPT, strerror(errno)));

		/* Create thread for processing that socket. */
		TRY(pthread_create(&child, NULL, handle_connection, (void *)client),
				ERROR(REASON_THREAD_CREATE, strerror(errno)));
		continue;
	}
end:
	if (code == KURUD_ERROR)
		close(client);
	return NULL;
}

void *handle_connection(void *arg) {
	int n; /* used to store recv fuction return */
	int layer; /* id of the layer requested */
	int command; /* the id of the command requested */
	int client; /* socket of the accepted client */

	/* Receive from *arg param the client socket descriptor */
	client = (int)arg;

	/*
	 * The format of the expected packet is:
	 * 
	 * [int layer_id]       : id of the layer
	 * [int command_id]     : id of the command to be requested
	 * [cont..]
	 * 
	 * If command_id == KURUD_COMMAND_LIST_REQUEST, 
	 *      then packet is requesting command list and [cont..] is empty;
	 *      else [cont..] is the argument list:
	 * [u_char command_args_len]        : size in bytes of the command_args
	 * [command_args[command_args_len]] : command_args string 
	 * 
	 * The packet sent in response to KURUD_COMMAND_LIST_REQUEST is
	 * [int command_size]               : size of the command_console_t array
	 * [command_console_t *commands]    : the command_console_t array
	 * 
	 * If command is any executable command, the response packet is:
	 * [int out_len] : size of the output
	 * [char *output]: the output for the command.
	 */

	/* Receive layer_id */

	n = recv(client, &layer, sizeof(layer), 0);
	ASSERT(n != -1, ERROR(REASON_SOCKET_RECEIVE, strerror(errno)));
	ASSERT(n >= sizeof(layer), ERR(REASON_COMMAND_PARSING));

	liblog_debug(MODULE_DAEMON,
			"console request: layer_id=%d:%s.", layer,
			(layer == LAYER_LINK) ? "(LAYER_LINK)" :
			(layer == LAYER_NET) ? "(LAYER_NET)" :
			(layer == LAYER_RELIABLE) ? "(LAYER_RELIABLE)" :
			(layer == LAYER_UNRELIABLE) ? "(LAYER_UNRELIABLE)" :
			"(UNKNOWN LAYER)");

	ASSERT(layer >= LAYER_LINK && layer <= LAYER_UNRELIABLE,
			ERROR(REASON_LAYER_INVALID, layer));

	/* Receive command_id */
	n = recv(client, &command, sizeof(command), 0);
	ASSERT(n != -1, ERROR(REASON_SOCKET_RECEIVE, strerror(errno)));
	ASSERT(n >= sizeof(command), ERR(REASON_COMMAND_PARSING));

	liblog_debug(MODULE_DAEMON, "console request: comand=%d.", command);

	if (command == KURUD_COMMAND_LIST_REQUEST) {
		/* Layer command list requested. */
		TRY(handle_command_list_request(client, layer),
				ERR(REASON_COMMAND_EXEC));
	} else {
		/* Layer command execution requested. */
		TRY(handle_execution_request(client, layer, command),
				ERR(REASON_COMMAND_EXEC));;
	}

end:
	close(client);
	return NULL;
}

int handle_command_list_request(int client, int layer) {
	command_console_t *commands;
	int size;
	char ack;
	int code;

	code = KURUD_ERROR;

	/* TODO descomentar os cases comentados quando eles estiverem 
	 * implementados. */
	size = 0;
	switch (layer) {
		case LAYER_LINK:
			kurud_link_console->console_get_commands(&commands, &size);
			break;
		case LAYER_NET:
			kurud_net_console->console_get_commands(&commands, &size);
			break;
			/*case LAYER_RELIABLE:
			 * freedomd_layer_reliable_console->console_get_command_list(
			 * &console_commands, &commands_size);
			 * break;
			 * case LAYER_UNRELIABLE:
			 * freedomd_layer_unreliable_console->console_get_command_list(
			 * &console_commands, &commands_size); */
		default:
			ERROR(REASON_LAYER_INVALID, layer);
			break;
	}

	/* Send the size of commands structure. */
	TRY(send(client, &size, sizeof(size), 0) != -1,
			ERROR(REASON_SOCKET_SEND, strerror(errno)));

	liblog_debug(MODULE_DAEMON,
			"console request: command_list returned (commands:%d).",
			size / sizeof(command_console_t));

	/* Sends console_commands structure if there is commands to send. */
	if (size > 0) {
		TRY(send(client, commands, size, 0) != -1,
				ERROR(REASON_SOCKET_SEND, strerror(errno)));
	}

	/* Terminate processing socket. */
	TRY(recv(client, &ack, sizeof(ack), 0), ERROR(REASON_SOCKET_RECEIVE,
					strerror(errno)));
	code = KURUD_OK;
end:
	close(client);
	return code;
}

int handle_execution_request(int client, int layer, int command) {
	int n;
	unsigned char args_len;
	char args[COMMAND_ARGS_LENGTH];
	char msg[COMMAND_RETURN_LENGTH];
	int msg_len;
	char ack;
	int code;

	code = KURUD_ERROR;

	/* Receive command args length in bytes. */
	n = recv(client, &args_len, sizeof(args_len), 0);
	ASSERT(n != -1, ERROR(REASON_SOCKET_RECEIVE, strerror(errno)));
	ASSERT(n >= sizeof(args_len), ERR(REASON_COMMAND_PARSING));

	liblog_debug(MODULE_DAEMON,
			"console request: command_args_len=%d.", args_len);

	/* Receive command_args. */
	n = recv(client, args, args_len, 0);
	ASSERT(n != -1, ERROR(REASON_SOCKET_RECEIVE, strerror(errno)));
	ASSERT(n == args_len && n < COMMAND_ARGS_LENGTH,
			ERR(REASON_COMMAND_PARSING));

	liblog_debug(MODULE_DAEMON,
			"console request: command_args=%s.", args);

	/* TODO descomentar os cases comentados quando eles estiverem 
	 * implementados. */

	/* Execute command. */
	args[n] = '\0';
	msg[0] = '\0';
	switch (layer) {
		case LAYER_LINK:
			TRY(kurud_link_console->console_execute(msg, COMMAND_RETURN_LENGTH,
							command, args), ERR(REASON_COMMAND_EXEC));
			break;
		case LAYER_NET:
			TRY(kurud_net_console->console_execute(msg, COMMAND_RETURN_LENGTH,
							command, args), ERR(REASON_COMMAND_EXEC));
			break;
			/*case LAYER_RELIABLE:
			 * freedomd_layer_reliable_console->console_execute_command(
			 * msg, COMMAND_RETURN_MESSAGE_MAX_LEN,
			 * command_id, command_args);
			 * break;
			 * case LAYER_UNRELIABLE:
			 * freedomd_layer_unreliable_console->console_execute_command(
			 * msg, COMMAND_RETURN_MESSAGE_MAX_LEN,
			 * command_id, command_args);
			 * break; */
		default:
			ERROR(REASON_LAYER_INVALID, layer);
			break;
	}

	/* Send the size of returned message. */
	msg_len = strlen(msg);
	TRY(send(client, &msg_len, sizeof(msg_len), 0) != -1,
			ERROR(REASON_SOCKET_SEND, strerror(errno)));

	/* Send returned message. */
	if (msg_len > 0) {
		TRY(send(client, msg, msg_len, 0) != -1,
				ERROR(REASON_SOCKET_SEND, strerror(errno)));
	}

	TRY(recv(client, &ack, sizeof(ack), 0) != -1,
			ERROR(REASON_SOCKET_RECEIVE, strerror(errno)));

	code = KURUD_OK;
end:
	close(client);
	return code;
}
