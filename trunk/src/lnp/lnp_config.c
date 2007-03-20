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
 * @file lnp_config.c Implementation of config routines for the LNP module.
 * @ingroup lnp
 */
 
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <dotconf.h>

#include <libfreedom/layers.h>
#include <libfreedom/liblog.h>
#include <util/util_crypto.h>

#include "lnp_config.h"
#include "lnp.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Max number of algorithms specified in cipher, hash ou MAC functions lists
 * (including the default ones).
 */
#define LNP_FUNCTION_LIST_SIZE 16

/*
 * Max number of bytes used for a function identifier (including the \0).
 */
#define LNP_FUNCTION_MAX_LENGTH 16

/**
 * Data type that stores a list of cryptographic functions.
 */
typedef struct {
	/* Number of algorithms stored on list. */
	int size;
	/* List of functions (1 is added for the default algorithms). */
	char list[LNP_FUNCTION_LIST_SIZE][LNP_FUNCTION_MAX_LENGTH];
} lnp_function_list_t;

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/**
 * Configures the number of keys that can be stored on the key store.
 */
static void set_key_store_size(int key_store_size);

/**
 * Configures the name of the file containing the public key.
 */
static void set_public_key_file(char *filename);

/**
 * Configures the name of the file containing the private key.
 */
static void set_private_key_file(char *filename);

/* 
 * Handles an integer parameter found on the configuration file parsing process.
 */
static DOTCONF_CB(handle_int);

/* 
 * Handles a filename parameter found on the configuration file parsing process.
 */
static DOTCONF_CB(handle_file);

/*
 * Handles an list of ciphers found on the configuration file parsing.
 */
static DOTCONF_CB(handle_ciphers);

/*
 * Handles an list of ciphers found on the configuration file parsing.
 */
static DOTCONF_CB(handle_hashes);

/*
 * Handles an list of ciphers found on the configuration file parsing.
 */
static DOTCONF_CB(handle_macs);

/*
 * Handles the errors found on file parsing.
 */
static FUNC_ERRORHANDLER(handle_error);

/*
 * Checks the sanity of the parameters used in the configuration.
 */
static int check_sanity();

/*
 * Copies the contents of source into destination, removing the duplicates found
 * on source.
 */
static void remove_duplicates(lnp_function_list_t *dst,
		lnp_function_list_t *src);
		
/*
 * Returns a string that specifies supported cryptographic functions. The format
 * of this string is "function1;function2;". */
static char *get_function_string(lnp_function_list_t *function_list);

/*
 * Copies max chars from string to function_sring. If string capacity is not
 * enough, function_string is copied until the last function name occurrence.
 */
static int copy_function_string(char *string, int max, char *function_string);

/*
 * Replaces the string out with the string in, dealocating out if it
 * is not NULL.
 */
static void replace_string(char **out, const char *in);

/*
 * Checks file existence.
 */
static int file_exists(const char *filename);

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/*
 * Default number of keys that can be stored on the key respository.
 */
#define DEFAULT_KEY_STORE_SIZE	256
/*
 * Default name of file containing the node public key.
 */
#define DEFAULT_PUBLIC_KEY		"public.key"
/*
 * Default name of file containing the node private key.
 */
#define DEFAULT_PRIVATE_KEY		"private.key"
/*
 * Default list of encryption algorithms.
 */
#define DEFAULT_CIPHER_LIST		{1, {"blowfish-cbc"}}
/*
 * Default list of hash functions.
 */
#define DEFAULT_HASH_LIST		{1, {"sha1"}}
/*
 * Default list of MAC algorithms.
 */
#define DEFAULT_MAC_LIST		{1, {"sha1-mac"}}

/*
 * Configuration file name.
 */
#define CONFIG_FILE_NAME		"lnp.conf"
/*
 * Keyword used in configuration file to set the size of the key repository.
 */
#define KEY_STORE_SIZE_KEYWORD	"key_store_size"
/*
 * Keyword used in configuration file to specify the name of the public key
 * file.
 */
#define PUBLIC_KEY_FILE_KEYWORD	"public_key_file"
/*
 * Keyword used in configuration file to specify the name of the private key
 * file.
 */
#define PRIVATE_KEY_FILE_KEYWORD "private_key_file"
/*
 * Keyword used in configuration file to set the list of encryption algorithms.
 */
#define CIPHER_LIST_KEYWORD		"cipher_list"
/*
 * Keyword used in configuration file to set the list of hash functions.
 */
#define HASH_LIST_KEYWORD		"hash_list"
/*
 * Keyword used in configuration file to set the list of MAC algorithms.
 */
#define MAC_LIST_KEYWORD		"mac_list"

/*
 * check_sanity() constants and return values.
 */
#define CONFIG_SANE 	0
#define CONFIG_NOT_SANE (-1)

/*
 * file_exists() return values.
 */
#define FILE_PRESENT		0
#define FILE_NOT_PRESENT	(-1)

/*
 * lnp_configure() constants.
 */
#define DOTCONF_FLAGS				NONE
#define DOTCONF_NO_CONTEXT_CHECKING	NULL

/**
 * Data type that stores the LNP configuration parameters that can be defined
 * in the configuration file.
 */
typedef struct {
	/** Capacity of the key store (in connections). */
	int key_store_size;
	/** File used to obtain the public key (in PEM format). */
	char *public_key;
	/** File used to obtain the private key (in PEM format). */
	char *private_key;
	/** Cipher algorithms list. */
	lnp_function_list_t cipher_list;
	/** Hash functions list. */
	lnp_function_list_t hash_list;
	/** MAC functions. */
	lnp_function_list_t mac_list;
} lnp_config_t;

/*
 * Data structure that defines the configuration options used by the parser.
 */
static const configoption_t options[] = {
	{KEY_STORE_SIZE_KEYWORD, ARG_INT, handle_int, NULL, CTX_ALL},
	{PUBLIC_KEY_FILE_KEYWORD, ARG_STR, handle_file, NULL, CTX_ALL},
	{PRIVATE_KEY_FILE_KEYWORD, ARG_STR, handle_file, NULL, CTX_ALL},
	{CIPHER_LIST_KEYWORD, ARG_LIST, handle_ciphers, NULL, CTX_ALL},
	{HASH_LIST_KEYWORD, ARG_LIST, handle_hashes, NULL, CTX_ALL},
	{MAC_LIST_KEYWORD, ARG_LIST, handle_macs, NULL, CTX_ALL},
	LAST_OPTION
};

/*
 * Default config.
 */
#define DEFAULT_CONFIG {		\
	DEFAULT_KEY_STORE_SIZE,		\
	DEFAULT_PUBLIC_KEY,			\
	DEFAULT_PRIVATE_KEY,		\
	DEFAULT_CIPHER_LIST,		\
	DEFAULT_HASH_LIST,			\
	DEFAULT_MAC_LIST			\
}

/*
 * Object that contains the default configuration parameters.
 */
static const lnp_config_t default_config = DEFAULT_CONFIG;

/*
 * Object that contains the current configuration parameters.
 */
static lnp_config_t current_config = DEFAULT_CONFIG;

/*
 * Strings that store supported functions.
 */
static char *cipher_string = NULL;
static char *hash_string = NULL;
static char *mac_string = NULL;

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

int lnp_configure(char *config_name) {
	configfile_t *config_file = NULL;
	
	if (config_name == NULL) {
		liblog_warn(LAYER_NET, "configuration file not sent by daemon,"
				"using default lnp.conf");
		config_name = CONFIG_FILE_NAME;
	}

	config_file = dotconf_create(config_name, options,
			DOTCONF_NO_CONTEXT_CHECKING, DOTCONF_FLAGS);

	if (config_file == NULL) {
		liblog_warn(LAYER_NET,
				"can't find config file, using default parameters.");
	} else {
		config_file->errorhandler = (dotconf_errorhandler_t) handle_error;
		liblog_debug(LAYER_NET, "configuration file opened.");

		if (dotconf_command_loop(config_file) == 0) {
			liblog_error(LAYER_NET, "error parsing config_file.");
		} else {
			liblog_debug(LAYER_NET, "configuration file parsed.");
		}
		dotconf_cleanup(config_file);	
		liblog_debug(LAYER_NET, "resources used by dotconf cleaned.");
	}

	if (check_sanity() == CONFIG_NOT_SANE) {
		liblog_warn(LAYER_NET,	"some parameters in configuration are not sane,"
				"using default values for them.");
	}
	liblog_debug(LAYER_NET, "configuration file sanity checked.");

	/* Generating strings that specify supported functions. */
	cipher_string = get_function_string(&current_config.cipher_list);
	hash_string = get_function_string(&current_config.hash_list);
	mac_string = get_function_string(&current_config.mac_list);

	liblog_debug(LAYER_NET, "cipher_string: %s.", cipher_string);
	liblog_debug(LAYER_NET, "hash_string: %s.", hash_string);
	liblog_debug(LAYER_NET, "mac_string: %s.", mac_string);
	
	if (cipher_string == NULL || hash_string == NULL || mac_string == NULL) {
		liblog_fatal(LAYER_NET, "can't allocate function specifiers.");
		return LNP_ERROR;
	}
	
	return LNP_OK;
}
/******************************************************************************/
void lnp_unconfigure() {
	memcpy(&current_config, &default_config, sizeof(lnp_config_t));

	/* Freeing strings allocated on lnp_configure(). */
	free(cipher_string);
	free(hash_string);
	free(mac_string);
	
	cipher_string = hash_string = mac_string = NULL;
}
/******************************************************************************/
util_cipher_function_t *lnp_cipher_search(char *cipher_list) {
	int i;
	char *cipher_list_copy;
	char *token;
	util_cipher_function_t *function;
	
	cipher_list_copy = (char *)malloc(strlen(cipher_list) + 1);
	if (cipher_list_copy == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.", strerror(errno));
		return NULL;
	}
	
	memcpy(cipher_list_copy, cipher_list, strlen(cipher_list) + 1);

	token = strtok((char *)cipher_list_copy, ";");
	while (token != NULL) {
		for (i = 0; i < current_config.cipher_list.size; i++) {
			if (strcmp(token, current_config.cipher_list.list[i]) == 0) {
				function = util_get_cipher(token);
				free(cipher_list_copy);
				return function;
			}
		}
		token = strtok(NULL, ";");
	}
	free(cipher_list_copy);

	liblog_error(LAYER_NET, "no cipher algorithm negotiated: %s.", 
			cipher_list);
	return NULL;
}
/******************************************************************************/
util_hash_function_t *lnp_hash_search(char *hash_list) {
	int i;
	char *hash_list_copy;
	char *token;
	util_hash_function_t *function;
	
	hash_list_copy = (char *)malloc(strlen(hash_list) + 1);
	if (hash_list_copy == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.", strerror(errno));
		return NULL;
	}
	
	memcpy(hash_list_copy, hash_list, strlen(hash_list) + 1);

	token = strtok((char *)hash_list_copy, ";");
	while (token != NULL) {
		for (i = 0; i < current_config.hash_list.size; i++) {
			if (strcmp(token, current_config.hash_list.list[i]) == 0) {
				function = util_get_hash(token);
				free(hash_list_copy);
				return function;
			}
		}
		token = strtok(NULL, ";");
	}
	
	free(hash_list_copy);
	
	liblog_error(LAYER_NET, "no hash algorithm negotiated: %s.", hash_list);
	return NULL;
}
/******************************************************************************/
util_mac_function_t *lnp_mac_search(char *mac_list) {
	int i;
	char *mac_list_copy;
	char *token;
	util_mac_function_t *function;
	
	mac_list_copy = (char *)malloc(strlen(mac_list) + 1);
	if (mac_list_copy == NULL) {
		liblog_fatal(LAYER_NET, "error in malloc: %s.", strerror(errno));
		return NULL;
	}
	
	memcpy(mac_list_copy, mac_list, strlen(mac_list) + 1);

	token = strtok((char *)mac_list_copy, ";");
	while (token != NULL) {
		for (i = 0; i < current_config.mac_list.size; i++) {
			if (strcmp(token, current_config.mac_list.list[i]) == 0) {
				function = util_get_mac(token);
				free(mac_list_copy);
				return function;
			}
		}
		token = strtok(NULL, ";");
	}
	
	free(mac_list_copy);

	liblog_error(LAYER_NET, "no mac algorithm negotiated: %s.", mac_list);
	return NULL;
}
/******************************************************************************/
int lnp_get_key_store_size() {
	return current_config.key_store_size;
}
/******************************************************************************/
char *lnp_get_public_key_file() {
	return current_config.public_key;
}
/******************************************************************************/
char *lnp_get_private_key_file() {
	return current_config.private_key;
}
/******************************************************************************/
int lnp_get_cipher_string(char *string, int max) {
	return copy_function_string(string, max, cipher_string);
}
/******************************************************************************/
int lnp_get_hash_string(char *string, int max) {
	return copy_function_string(string, max, hash_string);
}
/******************************************************************************/
int lnp_get_mac_string(char *string, int max) {
	return copy_function_string(string, max, mac_string);
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

void set_key_store_size(int key_store_size) {
	current_config.key_store_size = key_store_size;
}
/******************************************************************************/
void set_public_key_file(char *filename) {
	if (current_config.public_key != default_config.public_key) {
		replace_string(&current_config.public_key, filename);
	} else {
		current_config.public_key = filename;
	}
}
/******************************************************************************/
void set_private_key_file(char *filename) {
	if (current_config.private_key != default_config.private_key) {
		replace_string(&current_config.private_key, filename);
	} else {
		current_config.private_key = filename;
	}
}
/******************************************************************************/
void set_cipher_list(lnp_function_list_t *cipher_list) {
	remove_duplicates(&(current_config.cipher_list), cipher_list);		
}
/******************************************************************************/
void set_hash_list(lnp_function_list_t *hash_list) {
	remove_duplicates(&(current_config.hash_list), hash_list);	
}
/******************************************************************************/
void set_mac_list(lnp_function_list_t *mac_list) {
	remove_duplicates(&(current_config.mac_list), mac_list);	
}
/******************************************************************************/
DOTCONF_CB(handle_int) {

	if (strcmp(cmd->name, KEY_STORE_SIZE_KEYWORD) == 0) {
		liblog_debug(LAYER_NET, "key_store_size parameter found.");
		set_key_store_size(cmd->data.value);
		return NULL;
	}
	
	return NULL;
}
/******************************************************************************/
DOTCONF_CB(handle_file) {
	if (strcmp(cmd->name, PUBLIC_KEY_FILE_KEYWORD) == 0) {
		liblog_debug(LAYER_DAEMON, "public_key_file parameter found.");
		set_public_key_file(cmd->data.str);
		return NULL;
	}
	
	if (strcmp(cmd->name, PRIVATE_KEY_FILE_KEYWORD) == 0) {
		liblog_debug(LAYER_DAEMON, "private_key_file parameter found.");
		set_private_key_file(cmd->data.str);
		return NULL;
	}

	return NULL;
}
/******************************************************************************/
DOTCONF_CB(handle_ciphers) {
	int i;
	int size;
	lnp_function_list_t list;
	
	/* Dotconf only uses 16 arguments in lists, leaving in cmd->data[15]
	 * the unparsed rest of the string. So we use the first 15 arguments and 
	 * ignore the rest of them. */
	if (cmd->arg_count == CFG_MAX_VALUE) {
		liblog_warn(LAYER_NET, "too much ciphers listed in" \
				"configuration parameter, using the first 15 specified.");
		size = cmd->arg_count - 1;
	} else {
		size = cmd->arg_count;
	}
	
	/* Checking if functions specified are supported. */
	list.size = 0;
	for (i = 0; i < size; i++) {
		if (util_get_cipher(cmd->data.list[i]) != NULL) {
			strncpy(list.list[list.size++], cmd->data.list[i],
					LNP_FUNCTION_MAX_LENGTH);
		}
	}
	/* Copying the default cipher. */
	if (list.size > 0) {
	strncpy(list.list[list.size++], default_config.cipher_list.list[0],
			LNP_FUNCTION_MAX_LENGTH);
	}
	set_cipher_list(&list);
	
	return NULL;
}
/******************************************************************************/
DOTCONF_CB(handle_hashes) {
	int i;
	int size;
	lnp_function_list_t list;
	
	/* Dotconf only uses 16 arguments in lists, leaving in cmd->data[15]
	 * the unparsed rest of the string. So we use the first 15 arguments and 
	 * ignore the rest of them. */
	if (cmd->arg_count == CFG_MAX_VALUE) {
		liblog_warn(LAYER_NET, "too much hash functions listed in"
				"configuration parameter, using the first 15 specified.");
		size = cmd->arg_count - 1;
	} else {
		size = cmd->arg_count;
	}
	
	/* Checking if functions specified are supported. */
	list.size = 0;
	for (i = 0; i < size; i++) {
		if (util_get_hash(cmd->data.list[i]) != NULL) {
			strncpy(list.list[list.size++], cmd->data.list[i],
					LNP_FUNCTION_MAX_LENGTH);
		}
	}
	/* Copying the default hash function. */
	if (list.size > 0) {
		strncpy(list.list[list.size++], default_config.hash_list.list[0],
			LNP_FUNCTION_MAX_LENGTH);
	}
	set_hash_list(&list);	
	
	return NULL;
}
/******************************************************************************/
DOTCONF_CB(handle_macs) {
	int i;
	int size;
	lnp_function_list_t list;
	
	/* Dotconf only uses 16 arguments in lists, leaving in cmd->data[15]
	 * the unparsed rest of the string. So we use the first 15 arguments and 
	 * ignore the rest of them. */
	if (cmd->arg_count == CFG_MAX_VALUE) {
		liblog_warn(LAYER_NET, "too much MAC functions listed in" \
				"configuration parameter, using the first 15 specified.");
		size = cmd->arg_count - 1;
	} else {
		size = cmd->arg_count;
	}
	
	/* Checking if functions specified are supported. */
	list.size = 0;
	for (i = 0; i < size; i++) {
		if (util_get_mac(cmd->data.list[i]) != NULL) {
			strncpy(list.list[list.size++], cmd->data.list[i],
					LNP_FUNCTION_MAX_LENGTH);
		}
	}
	/* Copying the default MAC function. */
	if (list.size > 0) {
		strncpy(list.list[list.size++], default_config.mac_list.list[0],
				LNP_FUNCTION_MAX_LENGTH);
	}
	set_mac_list(&list);
	
	return NULL;
}
/******************************************************************************/
FUNC_ERRORHANDLER(handle_error) {

	switch (dc_errno) {
		case ERR_PARSE_ERROR:
			liblog_error(LAYER_NET, "line %lu: parse error.",
					configfile->line);
			break;
		case ERR_UNKNOWN_OPTION:
			liblog_error(LAYER_NET, "line %lu: unknown option.",
					configfile->line);
			break;
		case ERR_WRONG_ARG_COUNT:
			liblog_error(LAYER_NET, "line %lu: wrong arguments count.",
					configfile->line);
			break;
		case ERR_INCLUDE_ERROR:
			liblog_error(LAYER_NET, "line %lu: included file not found.",
					configfile->line);
			break;
		case ERR_NOACCESS:
			liblog_error(LAYER_NET, "acess denied.");
			break;
		default:
			liblog_error(LAYER_NET, "unknown error.");			
	}	
	
	lnp_unconfigure();
	liblog_error(LAYER_NET,
			"error in configuration file parsing, using defaults.");
	
	return 0;
}
/******************************************************************************/
int check_sanity() {
	int return_value = CONFIG_SANE;

	if (current_config.key_store_size < 1) {
		liblog_error(LAYER_NET, "key store size is too small.");
		current_config.key_store_size = DEFAULT_KEY_STORE_SIZE;
		return_value = CONFIG_NOT_SANE;
	}
	
	if (file_exists(current_config.public_key) == FILE_NOT_PRESENT) {
		liblog_error(LAYER_NET, "file not found. (%s)", 
				current_config.public_key);
		current_config.public_key = DEFAULT_PUBLIC_KEY;
		return_value = CONFIG_NOT_SANE;
	}
	
	if (file_exists(current_config.private_key) == FILE_NOT_PRESENT) {
		liblog_error(LAYER_NET, "file not found. (%s)", 
				current_config.private_key);
		current_config.private_key = DEFAULT_PRIVATE_KEY;
		return_value = CONFIG_NOT_SANE;
	}
	
	if (current_config.cipher_list.size <= 0) {
		liblog_error(LAYER_NET, "cipher_list is invalid.");
		memcpy(&current_config.cipher_list, &default_config.cipher_list,
				sizeof(lnp_function_list_t));
		return_value = CONFIG_NOT_SANE;
	}
	
	if (current_config.hash_list.size <= 0) {
		liblog_error(LAYER_NET, "hash_list is invalid.");
		memcpy(&current_config.hash_list, &default_config.hash_list,
				sizeof(lnp_function_list_t));
		return_value = CONFIG_NOT_SANE;
	}
	
	if (current_config.mac_list.size <= 0) {
		liblog_error(LAYER_NET, "mac_list is invalid.");
		memcpy(&current_config.mac_list, &default_config.mac_list,
				sizeof(lnp_function_list_t));
		return_value = CONFIG_NOT_SANE;
	}
	
	return return_value;
}
/******************************************************************************/
void remove_duplicates(lnp_function_list_t *dst, lnp_function_list_t *src) {
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
			strncpy(dst->list[dst->size], src->list[i],
				LNP_FUNCTION_MAX_LENGTH);
			(dst->size)++;
		}	
	}
}
/******************************************************************************/
char *get_function_string(lnp_function_list_t *function_list) {
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
		liblog_fatal(LAYER_NET, "error in malloc: %s.", strerror(errno));
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
int copy_function_string(char *string, int max, char *function_string) {
	int length;
	int i;
	
	length = strlen(function_string);
	/* If the string capacity is not enough, we truncate cipher_string to the
	 * last function name. */
	if (length + 1 > max) {
		liblog_warn(LAYER_NET, "too much functions specified, truncating"
				"to last function identifier.");
		for (i = max - 1; i > 0; i++) {
			if (function_string[i] == ';') {
				length = i;
				break;
			}
		}
		memcpy(string, function_string, length);
		string[length] = '\0';
		return LNP_ERROR;
	}
	
	memcpy(string, function_string, length + 1);
	
	return length + 1;	
}
/******************************************************************************/
void replace_string(char **out, const char *in) {
	int string_length;
	if (*out != NULL) {
		free(*out);	
	}
	string_length = strlen(in);
	*out = malloc(string_length + 1);
	if (*out != NULL) {
		strncpy(*out, in, string_length + 1);
	} else {
		liblog_error(LAYER_NET, "could not allocate memory for node_file"	\
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
