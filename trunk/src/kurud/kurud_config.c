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
 * @file kurud_config.c
 * 
 * Implementation of the configuration routines for the daemon.
 * 
 * @version $Header$
 * @ingroup kurud
 */

#include <stdlib.h>
#include <string.h>
#include <dotconf.h>

#include <liblog.h>
#include <liberror.h>

#include "kurud.h"
#include "kurud_config.h"
#include "kurud_err.h"

/*============================================================================*/
/* Private declarations                                                       */
/*============================================================================*/

/**
 * Default configuration file name.
 */
#define CONFIG_FILE				"kurud.conf"

/**
 * Length of configuration parameters.
 */
#define CONFIG_LENGTH			64

/**
 * Keyword used in configuration to set lock file path.
 */
#define KEYWORD_LOCK_FILE			"lock_file"
/**
 * Keyword used in configuration to set socket file path.
 */
#define KEYWORD_CONSOLE_FILE		"console_file"
/**
 * Keyword used in configuration to set the link module.
 */
#define KEYWORD_LINK_MODULE			"link_module"
/**
 * Keyword used in configuration to set the link config file.
 */
#define KEYWORD_LINK_CONFIG			"link_config"
/**
 * Keyword used in configuration to set the network module.
 */
#define KEYWORD_NET_MODULE			"net_module"
/**
 * Keyword used in configuration to set the network config file.
 */
#define KEYWORD_NET_CONFIG			"net_config"
/**
 * Keyword used in configuration to set the reliable transport module.
 */
#define KEYWORD_RELIABLE_MODULE		"reliable_module"
/**
 * Keyword used in configuration to set the reliable transport config file.
 */
#define KEYWORD_RELIABLE_CONFIG		"reliable_config"
/**
 * Keyword used in configuration to set the unreliable transport module.
 */
#define KEYWORD_UNRELIABLE_MODULE	"unreliable_module"
/**
 * Keyword used in configuration to set the unreliable transport config file.
 */
#define KEYWORD_UNRELIABLE_CONFIG	"unreliable_config"

/**
 * Handles a file parameter found on the configuration.
 */
static DOTCONF_CB(handle_file);

/**
 * Handles the errors found on configuration file parsing.
 */
static FUNC_ERRORHANDLER(handle_error);

/**
 * Configures the path of the console socket file.
 * 
 * @param[in] name      - the path to the socket file.
 */
static void set_console_file(char *name);

/**
 * Configures the path of the daemon lock file.
 * 
 * @param[in] name      - the path to the lock file.
 */
static void set_lock_file(char *name);

/**
 * Configures the filename of one of the modules.
 * 
 * @param[in] layer     - the layer to configure.
 * @param[in] name      - the module file
 */
static void set_module_file(int layer, char *name);

/**
 * Configures the configuration filename of one of the modules.
 * 
 * @param[in] layer     - the layer to configure
 * @param[in] name      - the configuration file
 */
static void set_module_config(int layer, char *name);

/**
 * Checks the sanity of the parameters used in the configuration.
 * 
 * @return KURUD_OK if the config is sane and KURUD_ERROR otherwise.
 */
static int check_config_sanity();

/**
 * Checks the sanity of one of the module parameters used in the configuration.
 * 
 * @param[in] file      - the module filename
 * @param[in] parameter - the name of the module related to that filename
 * @return KURUD_OK if the filename is not NULL and exists. 
 *      KURUD_ERROR otherwise.
 */
int check_module_sanity(const char *parameter, const char *file);

/**
 * Checks file existence.
 * 
 * @param[in] filename	- the file to test
 * @return KURUD_OK if the file exists or KURUD_ERROR if not.
 */
static int file_exists(const char *filename);

/*@{ */
/**
 * Configuration parsing library parameters.
 */
#define DOTCONF_FLAGS				NONE
#define DOTCONF_NO_CONTEXT_CHECKING	NULL
/*@} */

/**
 * Data type that stores the freedomd configuration parameters that can be 
 * defined in the configuration file.
 */
typedef struct {
	/** Lock file path. */
	char lock_file[CONFIG_LENGTH];
	/** Socket file path for the console. */
	char console_file[CONFIG_LENGTH];
	/** Name of the link module. */
	char link_module_file[CONFIG_LENGTH];
	/** Config file of the link module. */
	char link_config_file[CONFIG_LENGTH];
	/** Name of the network module. */
	char net_module_file[CONFIG_LENGTH];
	/** Config file of the network module. */
	char net_config_file[CONFIG_LENGTH];
	/** Name of the unreliable transport module. */
	char unreliable_module_file[CONFIG_LENGTH];
	/** Config file of the unreliable transport module. */
	char unreliable_config_file[CONFIG_LENGTH];
	/** Name of the reliable transport module. */
	char reliable_module_file[CONFIG_LENGTH];
	/** Config file of the reliable transport module. */
	char reliable_config_file[CONFIG_LENGTH];
} kurud_config_t;

/**
 * Data structure that defines the configuration options used by the parser.
 */
static configoption_t options[] = {
	{KEYWORD_LOCK_FILE, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_CONSOLE_FILE, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_LINK_MODULE, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_LINK_CONFIG, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_NET_MODULE, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_NET_CONFIG, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_UNRELIABLE_MODULE, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_UNRELIABLE_CONFIG, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_RELIABLE_MODULE, ARG_STR, handle_file, NULL, CTX_ALL},
	{KEYWORD_RELIABLE_CONFIG, ARG_STR, handle_file, NULL, CTX_ALL},
	LAST_OPTION
};

/**
 * Object that contains the current configuration parameters.
 */
static kurud_config_t current_config;

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int kurud_configure(char *file_name) {
	configfile_t *config_file = NULL;
	int code;

	code = KURUD_ERROR;

	if (file_name == NULL) {
		file_name = CONFIG_FILE;
	}

	/* Empty the current configuration. */
	memset(&current_config, 0, sizeof(kurud_config_t));

	config_file =
			dotconf_create(file_name, options, DOTCONF_NO_CONTEXT_CHECKING,
			DOTCONF_FLAGS);
	TRY(NULL != config_file, ERROR(REASON_CONFIG_NOT_FOUND, file_name));
	liblog_debug(MODULE_DAEMON, "configuration file opened %s", file_name);

	config_file->errorhandler = (dotconf_errorhandler_t) handle_error;

	TRY(dotconf_command_loop(config_file) != 0, ERR(REASON_CONFIG_PARSING));
	liblog_info(MODULE_DAEMON, "configuration file parsed");

	TRY(check_config_sanity(), ERR(REASON_CONFIG_SANITY));
	liblog_info(MODULE_DAEMON, "configuration file sanity checked");

	code = KURUD_OK;
end:
	if (config_file != NULL) {
		dotconf_cleanup(config_file);
		liblog_debug(MODULE_DAEMON, "resources used by dotconf cleaned.");
	}
	return code;
}

void kurud_unconfigure() {
	memset(&current_config, 0, sizeof(kurud_config_t));
}

char *kurud_get_lock_file() {
	return current_config.lock_file;
}

char *kurud_get_console_file() {
	return current_config.console_file;
}

char *kurud_get_module_file(int layer) {
	switch (layer) {
		case LAYER_LINK:
			return current_config.link_module_file;
		case LAYER_NET:
			return current_config.net_module_file;
		case LAYER_RELIABLE:
			return current_config.reliable_module_file;
		case LAYER_UNRELIABLE:
			return current_config.unreliable_module_file;
	}
	return NULL;
}

char *kurud_get_module_config(int layer) {
	switch (layer) {
		case LAYER_LINK:
			return current_config.link_config_file;
		case LAYER_NET:
			return current_config.net_config_file;
		case LAYER_RELIABLE:
			return current_config.reliable_config_file;
		case LAYER_UNRELIABLE:
			return current_config.unreliable_config_file;
	}
	return NULL;
}

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

void set_lock_file(char *name) {
	strncpy(current_config.lock_file, name, CONFIG_LENGTH);
}

void set_console_file(char *name) {
	strncpy(current_config.console_file, name, CONFIG_LENGTH);
}

void set_module_file(int layer, char *name) {
	switch (layer) {
		case LAYER_LINK:
			strncpy(current_config.link_module_file, name, CONFIG_LENGTH);
			break;
		case LAYER_NET:
			strncpy(current_config.net_module_file, name, CONFIG_LENGTH);
			break;
		case LAYER_RELIABLE:
			strncpy(current_config.reliable_module_file, name, CONFIG_LENGTH);
			break;
		case LAYER_UNRELIABLE:
			strncpy(current_config.unreliable_module_file, name, CONFIG_LENGTH);
			break;
	}
}

void set_module_config(int layer, char *name) {
	switch (layer) {
		case LAYER_LINK:
			strncpy(current_config.link_config_file, name, CONFIG_LENGTH);
			break;
		case LAYER_NET:
			strncpy(current_config.net_config_file, name, CONFIG_LENGTH);
			break;
		case LAYER_RELIABLE:
			strncpy(current_config.reliable_config_file, name, CONFIG_LENGTH);
			break;
		case LAYER_UNRELIABLE:
			strncpy(current_config.unreliable_config_file, name, CONFIG_LENGTH);
			break;
	}
}

int file_exists(const char *name) {
	FILE *file = NULL;
	int code;

	code = KURUD_ERROR;

	TRY(file = fopen(name, "r"), goto end);

	code = KURUD_OK;

end:
	if (file != NULL)
		fclose(file);
	return code;
}

DOTCONF_CB(handle_file) {
	if (strcmp(cmd->name, KEYWORD_LOCK_FILE) == 0) {
		liblog_debug(MODULE_DAEMON, "lock_file parameter found.");
		set_lock_file(cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_CONSOLE_FILE) == 0) {
		liblog_debug(MODULE_DAEMON, "console_file parameter found.");
		set_console_file(cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_LINK_MODULE) == 0) {
		liblog_debug(MODULE_DAEMON, "link_module parameter found.");
		set_module_file(LAYER_LINK, cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_LINK_CONFIG) == 0) {
		liblog_debug(MODULE_DAEMON, "link_config parameter found.");
		set_module_config(LAYER_LINK, cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_NET_MODULE) == 0) {
		liblog_debug(MODULE_DAEMON, "net_module parameter found.");
		set_module_file(LAYER_NET, cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_NET_CONFIG) == 0) {
		liblog_debug(MODULE_DAEMON, "net_config parameter found.");
		set_module_config(LAYER_NET, cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_RELIABLE_MODULE) == 0) {
		liblog_debug(MODULE_DAEMON, "reliable_module parameter found.");
		set_module_file(LAYER_RELIABLE, cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_RELIABLE_CONFIG) == 0) {
		liblog_debug(MODULE_DAEMON, "reliable_config parameter found.");
		set_module_config(LAYER_RELIABLE, cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_UNRELIABLE_MODULE) == 0) {
		liblog_debug(MODULE_DAEMON, "unreliable_module parameter found.");
		set_module_file(LAYER_UNRELIABLE, cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, KEYWORD_UNRELIABLE_CONFIG) == 0) {
		liblog_debug(MODULE_DAEMON, "unreliable_config parameter found.");
		set_module_config(LAYER_UNRELIABLE, cmd->data.str);
		return NULL;
	}

	return NULL;
}

FUNC_ERRORHANDLER(handle_error) {
	switch (dc_errno) {
		case ERR_PARSE_ERROR:
			liblog_error(MODULE_DAEMON,
					"line %lu: parse error.", configfile->line);
			break;
		case ERR_UNKNOWN_OPTION:
			liblog_error(MODULE_DAEMON,
					"line %lu: unknown option.", configfile->line);
			break;
		case ERR_WRONG_ARG_COUNT:
			liblog_error(MODULE_DAEMON,
					"line %lu: wrong arguments count.", configfile->line);
			break;
		case ERR_INCLUDE_ERROR:
			liblog_error(MODULE_DAEMON,
					"line %lu: included file not found.", configfile->line);
			break;
		case ERR_NOACCESS:
			liblog_error(MODULE_DAEMON, "acess denied.");
			break;
		default:
			liblog_error(MODULE_DAEMON, "unknown error.");
	}

	return 0;
}

int check_module_sanity(const char *parameter, const char *file) {
	int code;

	code = KURUD_ERROR;
	TRY(strlen(file) != 0, ERROR(REASON_PARAMETER_NOT_FOUND, parameter));

	TRY(file_exists(file), ERROR(REASON_FILE_NOT_FOUND, file));
end:
	return KURUD_OK;
}

int check_config_sanity() {
	/* Checks sanity of all module files. Config files for each module
	 * are optional, so these parameters are not checked. */
	char sanity = (check_module_sanity(KEYWORD_LINK_MODULE,
					current_config.link_module_file)) &&
					(check_module_sanity(KEYWORD_NET_MODULE,
					current_config.net_module_file)) &&
					(check_module_sanity(KEYWORD_RELIABLE_MODULE,
					current_config.reliable_module_file)) &&
					(check_module_sanity(KEYWORD_UNRELIABLE_MODULE,
					current_config.unreliable_module_file));

	return sanity ? KURUD_OK : KURUD_ERROR;
}
