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
 * @file kurud.c
 * 
 * Core functionality of the Kurupira daemon.
 * 
 * @version $Header$
 * @ingroup kurud
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

#include <liblog.h>
#include <liberror.h>

#include <kurupira/layers.h>
#include <kurupira/layer_link.h>

#include "kurud.h"
#include "kurud_err.h"
#include "kurud_config.h"
#include "kurud_console.h"

/*============================================================================*/
/* Public declarations                                                        */
/*============================================================================*/

layer_link_t *kurud_link_layer;
layer_net_t *kurud_net_layer;

layer_console_t *kurud_link_console;
layer_console_t *kurud_net_console;

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/*@{ */
/**
 * Used by initialization control.
 */
#define INITIALIZED 	(1)
#define NOT_INITIALIZED 0
/*@} */

/**
 * Lock file permissions.
 */
#define LOCKFILE_PERMS 0600

/**
 * Lock file descriptor.
 */
static int lock_descriptor;

/*@{ */
/**
 * Shared library descriptors used by the daemon.
 */
static void *link_handle;
static void *net_handle;
static void *reliable_handle;
static void *unreliable_handle;
/*@} */

/**
 * Condition variable indicating the end of the freedomd execution.
 */
static pthread_cond_t finish_condition;

/**
 * Mutex used to control finish state.
 */
static pthread_mutex_t finish_mutex;

/*@{ */
/**
 * Indicates if the various daemon componentes were initialized;
 */
static int threads_init = NOT_INITIALIZED;
static int console_init = NOT_INITIALIZED;
static int link_init = NOT_INITIALIZED;
static int net_init = NOT_INITIALIZED;
static int reliable_init = NOT_INITIALIZED;
static int unreliable_init = NOT_INITIALIZED;
/*@} */

/**
 * Try to load a symbol from a shared library using dlsym. If the symbol can't
 * be loaded, the function returned KURUD_ERROR;
 * 
 * @param[out] address      - the resulting address of the requested symbol
 * @param[in] handle        - the descriptor of the shared library
 * @param[in] symbol        - symbol to be loaded from the shared library.
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int load_symbol(void **address, void *handle, const char *symbol);

/**
 * Loads the link protocol shared library, which name is specified 
 * in the link_lib_name parameter. If any error occurs, we terminate
 * the execution of the daemon.
 * 
 * @param[in] library       - the path to the link module
 * @param[in] config        - the path to the configuration file
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int load_link_module(char *library, char *config);

/**
 * Unloads the link protocol shared library.
 * 
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int unload_link_module();

/**
 * Loads the net protocol shared library, which name is specified 
 * in the net_lib_name parameter.
 * 
 * @param[in] library       - the path to the network module
 * @param[in] config        - the path to the configuration file
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int load_net_module(char *library, char *config);

/**
 * Unloads the net protocol shared library.
 * 
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int unload_net_module();

/**
 * Loads the reliable transport protocol shared library, which name is specified 
 * in the reliable_lib_name parameter.
 * 
 * @param[in] library       - the path to the reliable module
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int load_reliable_module(char *library);

/**
 * Unloads the reliable transport protocol shared library.
 * 
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int unload_reliable_module();

/**
 * Loads the unreliable transport protocol shared library, which name is 
 * specified in the unreliable_lib_name parameter.
 * 
 * @param[in] library       - the path to the unreliable module
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int load_unreliable_module(char *library);

/**
 * Unloads the unreliable transport protocol shared library.
 * 
 * @return KURUD_OK if no error occurs, KURUD_ERROR otherwise.
 */
static int unload_unreliable_module();

/**
 * Handler for SIGINT signals.
 */
static void handler_sigint(int signal);

/**
 * Handler for SIGPIPE signals.
 */
static void handler_sigpipe(int signal);

/**
 * Tries to create the lock file. If the lock file already exists, the function
 * returns an error;
 * 
 * @returns 
 */
static int lock_file();

/**
 * Releases the lockfile.
 */
int unlock_file();

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int kurud_init(char *config_file) {
	int code;

	code = KURUD_ERROR;

	/* configure daemon */
	TRY(kurud_configure(config_file), ERR(REASON_CONFIGURATION));

	TRY(lock_file(), ERR(REASON_LOCK_FILE));

	TRY(pthread_cond_init(&finish_condition, NULL) == 0,
			ERR(REASON_CONDVAR_CREATE));

	TRY(pthread_mutex_init(&finish_mutex, NULL) == 0, ERR(REASON_MUTEX_CREATE));

	threads_init = INITIALIZED;

	/* load link module */
	TRY(load_link_module(kurud_get_module_file(LAYER_LINK),
					kurud_get_module_config(LAYER_LINK)),
			ERROR(REASON_LOAD_MODULE, MODULE_LINK));

	link_init = INITIALIZED;

	/* load net module */
	TRY(load_net_module(kurud_get_module_file(LAYER_NET),
					kurud_get_module_config(LAYER_NET)),
			ERROR(REASON_LOAD_MODULE, MODULE_NET));

	net_init = INITIALIZED;

	/* load reliable module */
	TRY(load_reliable_module(kurud_get_module_file(LAYER_RELIABLE)),
			ERROR(REASON_LOAD_MODULE, MODULE_RELIABLE));

	reliable_init = INITIALIZED;

	/* load unreliable module */
	/* load reliable module */
	TRY(load_unreliable_module(kurud_get_module_file(LAYER_UNRELIABLE)),
			ERROR(REASON_LOAD_MODULE, MODULE_UNRELIABLE));

	unreliable_init = INITIALIZED;

	TRY(kurud_console_init(), ERR(REASON_CONSOLE_INIT));

	console_init = INITIALIZED;

	TRY(signal(SIGINT, handler_sigint) != SIG_ERR, ERR(REASON_SIGNAL));

	TRY(signal(SIGPIPE, handler_sigpipe) != SIG_ERR, ERR(REASON_SIGNAL));

	code = KURUD_OK;
end:
	return code;
}

int kurud_finish() {
	int code;

	code = KURUD_ERROR;

	TRY(pthread_cond_broadcast(&finish_condition) == 0, ERR(REASON_PTHREADS));

	if (threads_init) {
		TRY(pthread_cond_destroy(&finish_condition) == 0,
				ERR(REASON_CONDVAR_DESTROY));

		TRY(pthread_mutex_destroy(&finish_mutex) == 0,
				ERR(REASON_MUTEX_DESTROY));

		threads_init = NOT_INITIALIZED;
	}

	if (console_init == INITIALIZED) {
		console_init = NOT_INITIALIZED;
		kurud_console_finish();
	}
	if (link_init == INITIALIZED) {
		link_init = NOT_INITIALIZED;
		unload_link_module();
	}
	if (net_init == INITIALIZED) {
		net_init = NOT_INITIALIZED;
		unload_net_module();
	}
	if (reliable_init == INITIALIZED) {
		reliable_init = NOT_INITIALIZED;
		unload_reliable_module();
	}
	if (unreliable_init == INITIALIZED) {
		unreliable_init = NOT_INITIALIZED;
		unload_unreliable_module();
	}

	TRY(unlock_file(), ERR(REASON_UNLOCK_FILE));

	kurud_unconfigure();

	code = KURUD_OK;
end:
	liblog_debug(MODULE_DAEMON, "kurud %s finalized.");
	return code;
}

int kurud_wait() {
	int code;

	code = KURUD_ERROR;

	TRY(pthread_mutex_lock(&finish_mutex) == 0, ERR(REASON_MUTEX_INVALID));
	TRY(pthread_cond_wait(&finish_condition, &finish_mutex) == 0,
			ERR(REASON_CONDVAR_INVALID));
	TRY(pthread_mutex_unlock(&finish_mutex) == 0, ERR(REASON_MUTEX_INVALID));

	code = KURUD_OK;
end:
	return code;
}

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

int load_symbol(void **address, void *handle, const char *symbol) {
	int code;

	code = KURUD_ERROR;

	TRY(*address = dlsym(handle, symbol), ERROR(REASON_DLSYM, dlerror()));

	code = KURUD_OK;
end:
	return code;
}

int load_link_module(char *library, char *config) {
	int code;
	void *(*get_interface) ();
	void *(*get_console) ();

	code = KURUD_ERROR;

	/* Load the link library. */
	TRY(link_handle = dlopen(library, RTLD_LAZY),
			ERROR(REASON_DLOPEN, dlerror()));

	TRY(load_symbol(*(void **)&get_interface, link_handle,
					"link_get_interface"), ERROR(REASON_LOAD_SYMBOL,
					dlerror()));

	kurud_link_layer = (layer_link_t *) get_interface();

	/* load the link_console structure */
	TRY(load_symbol(*(void **)&get_console, link_handle,
					"console_get_interface"), ERROR(REASON_LOAD_SYMBOL,
					dlerror()));

	kurud_link_console = (layer_console_t *) get_console();

	/* starts the link layer */
	TRY(kurud_link_layer->link_init(config), ERR(REASON_LINK_INIT));

	code = KURUD_OK;
end:
	return code;
}

int unload_link_module() {
	int code;

	code = KURUD_ERROR;

	if (kurud_link_layer) {
		if (kurud_link_layer->link_finish != NULL) {
			kurud_link_layer->link_finish();
		}
		TRY(dlclose(link_handle) != -1, ERROR(REASON_DLCLOSE, dlerror()));
		memset(&kurud_link_layer, 0, sizeof(kurud_link_layer));
		link_handle = NULL;
	}

	code = KURUD_OK;
end:
	return code;
}

int load_net_module(char *library, char *config) {
	int code;
	void *(*get_interface) ();
	void *(*get_console) ();

	code = KURUD_ERROR;

	/* Load the link library. */
	TRY(net_handle = dlopen(library, RTLD_LAZY),
			ERROR(REASON_DLOPEN, dlerror()));

	TRY(load_symbol(*(void **)&get_interface, net_handle, "net_get_interface"),
			ERROR(REASON_LOAD_SYMBOL, dlerror()));

	kurud_net_layer = (layer_net_t *) get_interface();

	/* load the link_console structure */
	TRY(load_symbol(*(void **)&get_console, net_handle,
					"console_get_interface"), ERROR(REASON_LOAD_SYMBOL,
					dlerror()));

	kurud_net_console = (layer_console_t *) get_console();

	/* starts the link layer */
	TRY(kurud_net_layer->net_init(config), ERR(REASON_NET_INIT));

	code = KURUD_OK;
end:
	return code;
}

int unload_net_module() {
	int code;

	code = KURUD_ERROR;

	if (net_handle) {
		if (kurud_net_layer->net_finish != NULL) {
			kurud_net_layer->net_finish();
		}
		TRY(dlclose(link_handle) != -1, ERROR(REASON_DLCLOSE, dlerror()));
		net_handle = NULL;
		memset(&kurud_net_layer, 0, sizeof(kurud_net_layer));
	}

	code = KURUD_OK;
end:
	return code;
}

int load_reliable_module(char *library) {
	return KURUD_OK;
}

int unload_reliable_module() {
	int code;

	code = KURUD_ERROR;

	if (reliable_handle) {
		dlclose(reliable_handle);
		reliable_handle = NULL;
		/*reliable_initialize = NULL;
		 * reliable_finalize = NULL; */
		/* memset(&freedomd_reliable_layer, 0, 
		 *      sizeof(freedomd_reliable_layer)); */
	}

	code = KURUD_OK;
	return code;
}

int load_unreliable_module(char *unreliable_lib_name) {
	return KURUD_OK;
}

int unload_unreliable_module() {
	int code;

	code = KURUD_ERROR;

	if (unreliable_handle) {
		dlclose(unreliable_handle);
		unreliable_handle = NULL;
		/*unreliable_initialize = NULL;
		 * unreliable_finalize = NULL; */
		/* memset(&freedomd_unreliable_layer, 0, 
		 *      sizeof(freedomd_unreliable_layer)); */
	}

	code = KURUD_OK;
	return code;
}

void handler_sigint(int signal) {
	liblog_debug(MODULE_DAEMON, "SIGINT received.");
	TRY(pthread_cond_signal(&finish_condition) == 0, ERR(REASON_PTHREADS));
end:
	return;
}

void handler_sigpipe(int signal) {
	liblog_debug(MODULE_DAEMON, "SIGPIPE received.");
	/* Ignore. This is necessary to handle the clients disconnections. */
}

int lock_file() {
	int code;

	code = KURUD_ERROR;

	lock_descriptor =
			open(kurud_get_lock_file(), O_WRONLY | O_CREAT | O_EXCL,
			LOCKFILE_PERMS);
	ASSERT(lock_descriptor != -1, ERROR(REASON_LOCK_FILE, strerror(errno)));

	code = KURUD_OK;
end:
	return code;
}

int unlock_file() {
	int code;

	code = KURUD_ERROR;

	if (lock_descriptor != -1) {
		TRY(unlink(kurud_get_lock_file()) != -1,
				ERROR(REASON_UNLINK, strerror(errno)));
		TRY(close(lock_descriptor) != -1,
				ERROR(REASON_SOCKET_CLOSE, strerror(errno)));
	}
	code = KURUD_OK;
end:
	return code;
}
