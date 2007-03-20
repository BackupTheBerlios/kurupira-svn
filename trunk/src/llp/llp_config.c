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
 * 
 * $Id: llp_config.c,v 1.58 2005/10/10 02:03:05 iamscared Exp $
 */

/**
 * @file llp_config.c Implementation of config routines for the LLP module.
 * @ingroup llp
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <dotconf.h>

#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>
#include <util/util_crypto.h>

#include "llp_config.h"
#include "llp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/**
 * Max number of algorithms specified in cipher, hash or MAC function lists
 * (including the default ones).
 */
#define LLP_FUNCTION_LIST_SIZE 16

/**
 * Max number of bytes used for a function identifier (including the trailing \\0).
 */
#define LLP_FUNCTION_MAX_LENGTH 16

/**
 * Data type that stores a list of cryptographic functions.
 */
typedef struct {
	/** Number of algorithms stored on list. */
	int size;
	/** List of functions. */
	char list[LLP_FUNCTION_LIST_SIZE][LLP_FUNCTION_MAX_LENGTH];
} llp_function_list_t;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/**
 * Configures the port.
 * 
 * @param[in] port      - the new port
 */
static void set_port(int port);

/**
 * Configures the minimum number of connections established.
 * 
 * @param[in] min       - the new minimum number of connections
 */
static void set_min_connections(int min);

/**
 * Configures the maximum number of connections established.
 * 
 * @param[in] max       - the new maximum number of connections.
 */
static void set_max_connections(int max);

/**
 * Configures the number of nodes that can be stored on cache.
 * 
 * @param[in] size      - the size of the nodes cache, in nodes.
 */
static void set_cache_size(int size);

/**
 * Configures the name of the file containing hosts to connect on demand.
 * 
 * @param[in] file_name - the file that contains known hosts.
 */
static void set_recent_nodes_file(char *file_name);

/**
 * Configures the name of the file containing hosts to connect at startup.
 * 
 * @param[in] file_name - the file that contains hosts to always connect.
 */
static void set_static_nodes_file(char *filename);

/**
 * Configures a new time for session expiration (in seconds). If a session is 
 * detected with the specified age, it is immediately closed.
 * 
 * @param[in] time      - the new expiration time.
 */
static void set_expiration_time(int time);

/**
 * Configures a new list of ciphers do be used.
 * 
 * @param[in]           - the new list of ciphers.
 */
void set_cipher_list(llp_function_list_t * cipher_list);

/**
 * Configures a new list of hash functions do be used.
 * 
 * @param[in]           - the new list of hash functions.
 */
void set_hash_list(llp_function_list_t * hash_list);

/**
 * Configures a new list of MAC functions do be used.
 * 
 * @param[in]           - the new list of MAC functions.
 */
void set_mac_list(llp_function_list_t * mac_list);

/**
 * Handles an integer parameter found on the configuration file parsing process.
 *
 */
static DOTCONF_CB(handle_int);

/**
 * Handles a filename parameter found on the configuration file parsing process.
 */
static DOTCONF_CB(handle_file);

/**
 * Handles a list of ciphers found on the configuration file parsing.
 */
static DOTCONF_CB(handle_ciphers);

/**
 * Handles a list of ciphers found on the configuration file parsing.
 */
static DOTCONF_CB(handle_hashes);

/**
 * Handles a list of ciphers found on the configuration file parsing.
 */
static DOTCONF_CB(handle_macs);

/**
 * Handles the errors found on file parsing.
 */
static FUNC_ERRORHANDLER(handle_error);

/**
 * Checks the sanity of the parameters used in the configuration.
 * 
 * @retval CONFIG_SANE      - if the configurations parameters make sense,
 * @retval CONFIG_NOT_SANE  - otherwise.
 */
static int check_sanity();

/**
 * Copies the contents of source into destination, removing the duplicates found
 * on source.
 * 
 * @param[out] dst      - the destination function list.
 * @param[in] src       - the source function list.
 */
static void copy_removing_duplicates(llp_function_list_t * dst, llp_function_list_t * src);

/**
 * Returns a string that specifies supported cryptographic functions. The string
 * is allocated to store all the function name and the format of this string is
 * "function1;function2;".
 * 
 * @param[out] list     - the list of functions supported.
 * @return an allocated string representing the functions.
 */
static char *get_function_string(llp_function_list_t * list);

/**
 * Copies max chars from src to dst. If string capacity is not
 * enough, function_string is copied until the last function name occurrence.
 * 
 * @param[out] dst      - buffer to receive the function string.
 * @param[in] max       - the buffer capacity.
 * @param[in] src       - source string.
 * @retval LLP_ERROR    - if function_string was truncated.
 * @return the number of bytes copied.
 */
static int copy_function_string(char *dst, int max, char *src);

/**
 * Replaces the string old with the string new, dealocating old if it
 * is not NULL.
 * 
 * @param[out] old      - the original string.
 * @param[in] new       - the new string.
 */
static void replace_string(char **old, const char *new);

/**
 * Checks file existence.
 * 
 * @param[in] file_name     - file name to test.
 * @retval FILE_PRESENT     - if file exists
 * @retval FILE_NOT_PRESENT - otherwise.
 */
static int file_exists(const char *file_name);

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/**
 * Default port.
 */
#define DEFAULT_PORT 			2357
/**
 * Default minimum number of connections established.
 */
#define DEFAULT_MIN_CONNECTIONS	10
/**
 * Default maximum number of connections established.
 */
#define DEFAULT_MAX_CONNECTIONS	100
/**
 * Default number of nodes on cache.
 */
#define DEFAULT_CACHE_SIZE		100
/**
 * Default expiration time for a session (1 day).
 */
#define DEFAULT_EXPIRATION_TIME	(24*60*60)
/**
 * Default name of file containing nodes to always connect.
 */
#define DEFAULT_STATIC_NODES	"llp.static"
/**
 * Default name of file containing recent nodes discovered.
 */
#define DEFAULT_RECENT_NODES	"llp.recent"
/**
 * Default list of encryption algorithms.
 */
#define DEFAULT_CIPHER_LIST		{1, {"blowfish-cbc"}}
/**
 * Default list of hash functions.
 */
#define DEFAULT_HASH_LIST		{1, {"sha1"}}
/**
 * Default list of MAC algorithms.
 */
#define DEFAULT_MAC_LIST		{1, {"sha1-mac"}}

/**
 * Configuration file name.
 */
#define CONFIG_FILE_NAME		"llp.conf"
/**
 * Keyword used in configuration file to set the module port.
 */
#define PORT_KEYWORD			"port"
/**
 * Keyword used in configuration file to set the number of minimum connections.
 */
#define MIN_CONNECTIONS_KEYWORD	"min_connections"
/**
 * Keyword used in configuration file to set the number of maximum connections.
 */
#define MAX_CONNECTIONS_KEYWORD	"max_connections"
/**
 * Keyword used in configuration file to set the size of nodes cache.
 */
#define CACHE_SIZE_KEYWORD		"cache_size"
/**
 * Keyword used in configuration file to set the session expiration time.
 */
#define	EXPIRATION_TIME_KEYWORD	"expiration_time"
/**
 * Keyword used in configuration file to specify the name of the static nodes
 * file.
 */
#define STATIC_NODES_FILE_KEYWORD	"static_nodes_file"
/**
 * Keyword used in configuration file to specify the name of the recent nodes
 * file.
 */
#define RECENT_NODES_FILE_KEYWORD	"recent_nodes_file"
/**
 * Keyword used in configuration file to set the list of encryption algorithms.
 */
#define CIPHER_LIST_KEYWORD		"cipher_list"
/**
 * Keyword used in configuration file to set the list of hash functions.
 */
#define HASH_LIST_KEYWORD		"hash_list"
/**
 * Keyword used in configuration file to set the list of MAC algorithms.
 */
#define MAC_LIST_KEYWORD		"mac_list"

/*@{ */
/**
 * check_sanity() constant or return value.
 */
#define ONE_MINUTE 		60
#define MAX_PORT_NUMBER	65535
#define CONFIG_SANE 	0
#define CONFIG_NOT_SANE (-1)
/*@} */

/*@{ */
/**
 * file_exists() return value.
 */
#define FILE_PRESENT		0
#define FILE_NOT_PRESENT	(-1)
/*@} */

/*@{ */
/**
 * llp_configure() constant.
 */
#define DOTCONF_FLAGS				NONE
#define DOTCONF_NO_CONTEXT_CHECKING	NULL
/*@} */

/**
 * Data type that stores the LLP configuration parameters that can be defined
 * in the configuration file.
 */
typedef struct {
	/** Port to listen for connections. */
	int port;
	/** Minimum number of connections opened. */
	int min_connections;
	/** Maximum number of connections opened. */
	int max_connections;
	/** Nodes cache size (in nodes). */
	int cache_size;
	/** Session expiration time (in seconds). */
	int expiration_time;
	/** File used to obtain nodes that this node will always try to connect. */
	char *static_nodes;
	/** File used to obtain nodes that were recently received by this node. */
	char *recent_nodes;
	/** Cipher algorithms list. */
	llp_function_list_t cipher_list;
	/** Hash functions list. */
	llp_function_list_t hash_list;
	/** MAC functions. */
	llp_function_list_t mac_list;
} llp_config_t;

/**
 * Data structure that defines the configuration options used by the parser.
 */
static const configoption_t options[] = {
	{PORT_KEYWORD, ARG_INT, handle_int, NULL, CTX_ALL},
	{MIN_CONNECTIONS_KEYWORD, ARG_INT, handle_int, NULL, CTX_ALL},
	{MAX_CONNECTIONS_KEYWORD, ARG_INT, handle_int, NULL, CTX_ALL},
	{CACHE_SIZE_KEYWORD, ARG_INT, handle_int, NULL, CTX_ALL},
	{EXPIRATION_TIME_KEYWORD, ARG_INT, handle_int, NULL, CTX_ALL},
	{STATIC_NODES_FILE_KEYWORD, ARG_STR, handle_file, NULL, CTX_ALL},
	{RECENT_NODES_FILE_KEYWORD, ARG_STR, handle_file, NULL, CTX_ALL},
	{CIPHER_LIST_KEYWORD, ARG_LIST, handle_ciphers, NULL, CTX_ALL},
	{HASH_LIST_KEYWORD, ARG_LIST, handle_hashes, NULL, CTX_ALL},
	{MAC_LIST_KEYWORD, ARG_LIST, handle_macs, NULL, CTX_ALL},
	LAST_OPTION
};

/**
 * Default config.
 */
#define DEFAULT_CONFIG { 		\
	DEFAULT_PORT,				\
	DEFAULT_MIN_CONNECTIONS,	\
	DEFAULT_MAX_CONNECTIONS,	\
	DEFAULT_CACHE_SIZE,			\
	DEFAULT_EXPIRATION_TIME,	\
	DEFAULT_STATIC_NODES,		\
	DEFAULT_RECENT_NODES,		\
	DEFAULT_CIPHER_LIST,		\
	DEFAULT_HASH_LIST,			\
	DEFAULT_MAC_LIST			\
}

/**
 * Default configuration parameters.
 */
static const llp_config_t default_config = DEFAULT_CONFIG;

/**
 * Current configuration parameters.
 */
static llp_config_t current_config = DEFAULT_CONFIG;

/*@{ */
/**
 * Strings that store supported functions.
 */
static char *cipher_string = NULL;
static char *hash_string = NULL;
static char *mac_string = NULL;
/*@} */

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int llp_configure(char *config_name) {
	configfile_t *config_file = NULL;

	if (config_name == NULL) {
		liblog_warn(LAYER_LINK, "configuration file not sent by daemon," "using default llp.conf");
		config_name = CONFIG_FILE_NAME;
	}

	config_file = dotconf_create(config_name, options, DOTCONF_NO_CONTEXT_CHECKING, DOTCONF_FLAGS);

	if (config_file == NULL) {
		liblog_warn(LAYER_LINK, "can't find config file, using default parameters.");
	} else {
		config_file->errorhandler = (dotconf_errorhandler_t) handle_error;

		if (dotconf_command_loop(config_file) == 0) {
			liblog_error(LAYER_LINK, "error parsing config_file.");
		} else {
			liblog_debug(LAYER_LINK, "configuration file parsed.");
		}
		dotconf_cleanup(config_file);
	}

	if (check_sanity() == CONFIG_NOT_SANE) {
		liblog_warn(LAYER_LINK, "some parameters in configuration are not sane,"
				"using default values for them.");
	}
	liblog_debug(LAYER_LINK, "configuration file sanity checked.");

	/* Generating strings that specify supported functions. */
	cipher_string = get_function_string(&current_config.cipher_list);
	hash_string = get_function_string(&current_config.hash_list);
	mac_string = get_function_string(&current_config.mac_list);

	liblog_debug(LAYER_LINK, "cipher_string: %s.", cipher_string);
	liblog_debug(LAYER_LINK, "hash_string: %s.", hash_string);
	liblog_debug(LAYER_LINK, "mac_string: %s.", mac_string);

	if (cipher_string == NULL || hash_string == NULL || mac_string == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return LLP_ERROR;
	}

	return LLP_OK;
}

/******************************************************************************/
void llp_unconfigure() {
	memcpy(&current_config, &default_config, sizeof(llp_config_t));

	/* Freeing strings allocated on llp_configure(). */
	free(cipher_string);
	free(hash_string);
	free(mac_string);

	cipher_string = hash_string = mac_string = NULL;
}

/******************************************************************************/
util_cipher_function_t *llp_search_cipher(char *ciphers) {
	int i;
	char *ciphers_copy;
	char *token;
	util_cipher_function_t *function;

	/* We duplicate the string, because strtok is destructive. */
	ciphers_copy = (char *)malloc(strlen(ciphers) + 1);
	if (ciphers_copy == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return NULL;
	}

	memcpy(ciphers_copy, ciphers, strlen(ciphers) + 1);

	token = strtok((char *)ciphers_copy, ";");
	while (token != NULL) {
		for (i = 0; i < current_config.cipher_list.size; i++) {
			if (strcmp(token, current_config.cipher_list.list[i]) == 0) {
				function = util_get_cipher(token);
				free(ciphers_copy);
				return function;
			}
		}
		token = strtok(NULL, ";");
	}
	free(ciphers_copy);

	liblog_error(LAYER_LINK, "no cipher algorithm negotiated: %s.", ciphers);
	return NULL;
}

/******************************************************************************/
util_hash_function_t *llp_search_hash(char *hashes) {
	int i;
	char *hashes_copy;
	char *token;
	util_hash_function_t *function;

	/* We duplicate the string, because strtok is destructive. */
	hashes_copy = (char *)malloc(strlen(hashes) + 1);
	if (hashes_copy == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return NULL;
	}

	memcpy(hashes_copy, hashes, strlen(hashes) + 1);

	token = strtok((char *)hashes_copy, ";");
	while (token != NULL) {
		for (i = 0; i < current_config.hash_list.size; i++) {
			if (strcmp(token, current_config.hash_list.list[i]) == 0) {
				function = util_get_hash(token);
				free(hashes_copy);
				return function;
			}
		}
		token = strtok(NULL, ";");
	}

	free(hashes_copy);

	liblog_error(LAYER_LINK, "no hash algorithm negotiated: %s.", hashes);
	return NULL;
}

/******************************************************************************/
util_mac_function_t *llp_search_mac(char *macs) {
	int i;
	char *macs_copy;
	char *token;
	util_mac_function_t *function;

	/* We duplicate the string, because strtok is destructive. */
	macs_copy = (char *)malloc(strlen(macs) + 1);
	if (macs_copy == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return NULL;
	}

	memcpy(macs_copy, macs, strlen(macs) + 1);

	token = strtok((char *)macs_copy, ";");
	while (token != NULL) {
		for (i = 0; i < current_config.mac_list.size; i++) {
			if (strcmp(token, current_config.mac_list.list[i]) == 0) {
				function = util_get_mac(token);
				free(macs_copy);
				return function;
			}
		}
		token = strtok(NULL, ";");
	}

	free(macs_copy);

	liblog_error(LAYER_LINK, "no MAC algorithm negotiated: %s.", macs);
	return NULL;
}

/******************************************************************************/
int llp_get_port() {
	return current_config.port;
}

/******************************************************************************/
int llp_get_min_connections() {
	return current_config.min_connections;
}

/******************************************************************************/
int llp_get_max_connections() {
	return current_config.max_connections;
}

/******************************************************************************/
int llp_get_cache_size() {
	return current_config.cache_size;
}

/******************************************************************************/
int llp_get_expiration_time() {
	return current_config.expiration_time;
}

/******************************************************************************/
char *llp_get_recent_nodes_file() {
	return current_config.recent_nodes;
}

/******************************************************************************/
char *llp_get_static_nodes_file() {
	return current_config.static_nodes;
}

/******************************************************************************/
int llp_get_cipher_string(char *string, int max) {
	return copy_function_string(string, max, cipher_string);
}

/******************************************************************************/
int llp_get_hash_string(char *string, int max) {
	return copy_function_string(string, max, hash_string);
}

/******************************************************************************/
int llp_get_mac_string(char *string, int max) {
	return copy_function_string(string, max, mac_string);
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

void set_port(int port) {
	current_config.port = port;
}

/******************************************************************************/
void set_min_connections(int min_connections) {
	current_config.min_connections = min_connections;
}

/******************************************************************************/
void set_max_connections(int max_connections) {
	current_config.max_connections = max_connections;
}

/******************************************************************************/
void set_cache_size(int cache_size) {
	current_config.cache_size = cache_size;
}

/******************************************************************************/
void set_static_nodes_file(char *filename) {
	replace_string(&current_config.recent_nodes, filename);
}

/******************************************************************************/
void set_recent_nodes_file(char *filename) {
	replace_string(&current_config.static_nodes, filename);
}

/******************************************************************************/
void set_expiration_time(int expiration_time) {
	current_config.expiration_time = expiration_time;
}

/******************************************************************************/
void set_cipher_list(llp_function_list_t * cipher_list) {
	copy_removing_duplicates(&(current_config.cipher_list), cipher_list);
}

/******************************************************************************/
void set_hash_list(llp_function_list_t * hash_list) {
	copy_removing_duplicates(&(current_config.hash_list), hash_list);
}

/******************************************************************************/
void set_mac_list(llp_function_list_t * mac_list) {
	copy_removing_duplicates(&(current_config.mac_list), mac_list);
}

/******************************************************************************/
DOTCONF_CB(handle_int) {

	if (strcmp(cmd->name, PORT_KEYWORD) == 0) {
		liblog_debug(LAYER_LINK, "port parameter found.");
		set_port(cmd->data.value);
		return NULL;
	}

	if (strcmp(cmd->name, MIN_CONNECTIONS_KEYWORD) == 0) {
		liblog_debug(LAYER_LINK, "min_connections parameter found.");
		set_min_connections(cmd->data.value);
		return NULL;
	}

	if (strcmp(cmd->name, MAX_CONNECTIONS_KEYWORD) == 0) {
		liblog_debug(LAYER_LINK, "max_connections parameter found.");
		set_max_connections(cmd->data.value);
		return NULL;
	}

	if (strcmp(cmd->name, CACHE_SIZE_KEYWORD) == 0) {
		liblog_debug(LAYER_LINK, "cache_size parameter found.");
		set_cache_size(cmd->data.value);
		return NULL;
	}

	if (strcmp(cmd->name, EXPIRATION_TIME_KEYWORD) == 0) {
		liblog_debug(LAYER_LINK, "expiration_time parameter found.");
		set_expiration_time(cmd->data.value);
		return NULL;
	}

	return NULL;
}

/******************************************************************************/
DOTCONF_CB(handle_file) {
	if (strcmp(cmd->name, RECENT_NODES_FILE_KEYWORD) == 0) {
		liblog_debug(LAYER_DAEMON, "recent_nodes_file parameter found.");
		set_recent_nodes_file(cmd->data.str);
		return NULL;
	}

	if (strcmp(cmd->name, STATIC_NODES_FILE_KEYWORD) == 0) {
		liblog_debug(LAYER_DAEMON, "recent_nodes_file parameter found.");
		set_static_nodes_file(cmd->data.str);
		return NULL;
	}

	return NULL;
}

/******************************************************************************/
DOTCONF_CB(handle_ciphers) {
	int i;
	int size;
	llp_function_list_t list;

	/* Dotconf only uses 16 arguments in lists, leaving in cmd->data[15]
	 * the unparsed rest of the string. So we use the first 15 arguments and 
	 * ignore the rest of them. */
	if (cmd->arg_count == CFG_VALUES) {
		liblog_warn(LAYER_LINK, "too much ciphers listed in"
				"configuration parameter, using the first 15 specified.");
		size = cmd->arg_count - 1;
	} else {
		size = cmd->arg_count;
	}

	/* Checking if functions specified are supported. */
	list.size = 0;
	for (i = 0; i < size; i++) {
		if (util_get_cipher(cmd->data.list[i]) != NULL) {
			strncpy(list.list[list.size++], cmd->data.list[i], LLP_FUNCTION_MAX_LENGTH);
		}
	}
	/* Copying the default cipher. */
	if (list.size > 0) {
		strncpy(list.list[list.size++], default_config.cipher_list.list[0],
				LLP_FUNCTION_MAX_LENGTH);
	}
	set_cipher_list(&list);

	return NULL;
}

/******************************************************************************/
DOTCONF_CB(handle_hashes) {
	int i;
	int size;
	llp_function_list_t list;

	/* Dotconf only uses 16 arguments in lists, leaving in cmd->data[15]
	 * the unparsed rest of the string. So we use the first 15 arguments and 
	 * ignore the rest of them. */
	if (cmd->arg_count == CFG_VALUES) {
		liblog_warn(LAYER_LINK, "too much hash functions listed in"
				"configuration parameter, using the first 15 specified.");
		size = cmd->arg_count - 1;
	} else {
		size = cmd->arg_count;
	}

	/* Checking if functions specified are supported. */
	list.size = 0;
	for (i = 0; i < size; i++) {
		if (util_get_hash(cmd->data.list[i]) != NULL) {
			strncpy(list.list[list.size++], cmd->data.list[i], LLP_FUNCTION_MAX_LENGTH);
		}
	}
	/* Copying the default hash function. */
	if (list.size > 0) {
		strncpy(list.list[list.size++], default_config.hash_list.list[0], LLP_FUNCTION_MAX_LENGTH);
	}
	set_hash_list(&list);

	return NULL;
}

/******************************************************************************/
DOTCONF_CB(handle_macs) {
	int i;
	int size;
	llp_function_list_t list;

	/* Dotconf only uses 16 arguments in lists, leaving in cmd->data[15]
	 * the unparsed rest of the string. So we use the first 15 arguments and 
	 * ignore the rest of them. */
	if (cmd->arg_count == CFG_VALUES) {
		liblog_warn(LAYER_LINK, "too much MAC functions listed in"
				"configuration parameter, using the first 15 specified.");
		size = cmd->arg_count - 1;
	} else {
		size = cmd->arg_count;
	}

	/* Checking if functions specified are supported. */
	list.size = 0;
	for (i = 0; i < size; i++) {
		if (util_get_mac(cmd->data.list[i]) != NULL) {
			strncpy(list.list[list.size++], cmd->data.list[i], LLP_FUNCTION_MAX_LENGTH);
		}
	}
	/* Copying the default MAC function. */
	if (list.size > 0) {
		strncpy(list.list[list.size++], default_config.mac_list.list[0], LLP_FUNCTION_MAX_LENGTH);
	}
	set_mac_list(&list);

	return NULL;
}

/******************************************************************************/
FUNC_ERRORHANDLER(handle_error) {

	switch (dc_errno) {
case ERR_PARSE_ERROR:
			liblog_error(LAYER_LINK, "line %lu: parse error.", configfile->line);
			break;
case ERR_UNKNOWN_OPTION:
			liblog_error(LAYER_LINK, "line %lu: unknown option.", configfile->line);
			break;
case ERR_WRONG_ARG_COUNT:
			liblog_error(LAYER_LINK, "line %lu: wrong arguments count.", configfile->line);
			break;
case ERR_INCLUDE_ERROR:
			liblog_error(LAYER_LINK, "line %lu: included file not found.", configfile->line);
			break;
case ERR_NOACCESS:
			liblog_error(LAYER_LINK, "acess denied.");
			break;
default:
			liblog_error(LAYER_LINK, "unknown error.");
	}

	llp_unconfigure();
	liblog_error(LAYER_LINK, "error in configuration file parsing, using defaults.");

	return 0;
}

/******************************************************************************/
int check_sanity() {
	int return_value = CONFIG_SANE;

	if (current_config.port > MAX_PORT_NUMBER) {
		liblog_error(LAYER_LINK, "invalid port.");
		current_config.port = DEFAULT_PORT;
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.min_connections <= 0) {
		liblog_error(LAYER_LINK, "min_connections must be a positive integer.");
		current_config.min_connections = DEFAULT_MIN_CONNECTIONS;
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.max_connections <= 0 || current_config.max_connections >= 255) {
		liblog_error(LAYER_LINK, "max_connections must be a positive integer between 1 and 255.");
		current_config.max_connections = DEFAULT_MAX_CONNECTIONS;
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.max_connections < current_config.min_connections) {
		liblog_error(LAYER_LINK, "max connections must be greater than min_connections.");
		current_config.min_connections = DEFAULT_MIN_CONNECTIONS;
		current_config.max_connections = DEFAULT_MAX_CONNECTIONS;
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.expiration_time <= ONE_MINUTE) {
		liblog_error(LAYER_LINK, "session expiration time too small.");
		current_config.expiration_time = DEFAULT_EXPIRATION_TIME;
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.cache_size < 1) {
		liblog_error(LAYER_LINK, "cache size too small.");
		current_config.cache_size = DEFAULT_CACHE_SIZE;
		return_value = CONFIG_NOT_SANE;
	}

	if (file_exists(current_config.recent_nodes) == FILE_NOT_PRESENT) {
		liblog_error(LAYER_LINK, "file not found. (%s)", current_config.recent_nodes);
		current_config.recent_nodes = DEFAULT_RECENT_NODES;
		return_value = CONFIG_NOT_SANE;
	}

	if (file_exists(current_config.static_nodes) == FILE_NOT_PRESENT) {
		liblog_error(LAYER_LINK, "file not found. (%s)", current_config.static_nodes);
		current_config.static_nodes = DEFAULT_STATIC_NODES;
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.cipher_list.size <= 0) {
		liblog_error(LAYER_LINK, "cipher_list is invalid.");
		memcpy(&current_config.cipher_list, &default_config.cipher_list,
				sizeof(llp_function_list_t));
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.hash_list.size <= 0) {
		liblog_error(LAYER_LINK, "hash_list is invalid.");
		memcpy(&current_config.hash_list, &default_config.hash_list, sizeof(llp_function_list_t));
		return_value = CONFIG_NOT_SANE;
	}

	if (current_config.mac_list.size <= 0) {
		liblog_error(LAYER_LINK, "mac_list is invalid.");
		memcpy(&current_config.mac_list, &default_config.mac_list, sizeof(llp_function_list_t));
		return_value = CONFIG_NOT_SANE;
	}

	return return_value;
}

/******************************************************************************/
void copy_removing_duplicates(llp_function_list_t * dst, llp_function_list_t * src) {
	int i, j;
	int found;

	dst->size = 0;
	for (i = 0; i < src->size; i++) {
		found = 0;
		for (j = 0; j < dst->size; j++)
			if (strcmp(dst->list[j], src->list[i]) == 0) {
				found = 1;
				break;
			}
		if (!found) {
			strncpy(dst->list[dst->size], src->list[i], LLP_FUNCTION_MAX_LENGTH);
			(dst->size)++;
		}
	}
}

/******************************************************************************/
char *get_function_string(llp_function_list_t * function_list) {
	int i;
	int length;
	char *string;

	length = 0;
	for (i = 0; i < function_list->size; i++) {
		length += strlen(function_list->list[i]);
	}

	/* Allocating string (length chars plus i ";" plus terminating \0). */
	string = (char *)malloc(length + i + 1);
	if (string == NULL) {
		liblog_fatal(LAYER_LINK, "error in malloc: %s.", strerror(errno));
		return NULL;
	}

	/* We start with the null string. */
	string[0] = '\0';
	for (i = 0; i < function_list->size; i++) {
		length = strlen(function_list->list[i]);
		strncat(string, function_list->list[i], length);
		strncat(string, ";", 1);
	}

	return string;
}

/******************************************************************************/
int copy_function_string(char *dst, int max, char *src) {
	int length;
	int i;

	length = strlen(src);
	/* If the string capacity is not enough, we truncate src to the last
	 * function name. */
	if (length + 1 > max) {
		liblog_warn(LAYER_LINK, "too much functions specified, truncating"
				"to last function identifier.");
		for (i = max - 1; i > 0; i++) {
			if (src[i] == ';') {
				length = i;
				break;
			}
		}
		memcpy(dst, src, length);
		dst[length] = '\0';
		return LLP_ERROR;
	}

	memcpy(dst, src, length + 1);

	return length + 1;
}

/******************************************************************************/
void replace_string(char **old, const char *new) {
	int length;

	if (*old != NULL) {
		free(*old);
	}
	length = strlen(new);
	*old = malloc(length + 1);
	if (*old != NULL) {
		strncpy(*old, new, length + 1);
	} else {
		liblog_error(LAYER_LINK, "could not allocate memory for node_file"
				"parameter. Using NULL file.");
	}
}

/******************************************************************************/
int file_exists(const char *filename) {
	int ret;
	FILE *file;

	file = fopen(filename, "r");
	if (file == NULL) {
		ret = FILE_NOT_PRESENT;
	} else {
		ret = FILE_PRESENT;
		fclose(file);
	}

	return ret;
}

/******************************************************************************/
