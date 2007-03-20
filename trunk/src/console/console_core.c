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
 * @file console_core.c Module that reads commands from the user and sends them
 * 		to the daemon through the libfreedom console library (libconsole).
 * @ingroup console
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <libfreedom/libconsole.h>
#include <libfreedom/layers.h>

#include "console_core.h"

/*============================================================================*/
/* Private data definitions.                                                  */
/*============================================================================*/

/**
 * Default prompt used at the console.
 */
#define DEFAULT_PROMPT		"libfreedom# "

/**
 * Expanded prompt used at the console.
 */
#define PROMPT_FORMAT		"libfreedom[%s]# "

/**
 * Max number of chars for the expanded identifier.
 */
#define PROMPT_MAX_CHARS	30

/**
 * The command name used to exit the console.
 */
#define EXIT_COMMAND_NAME	"exit"

/**
 * Allow parsing of the ~/.inputrc file .
 */
#define READLINE_NAME 		"libfreedom"

/**
 * Indicates that the console is in "root directory mode". This allow
 * users to choose one layer as entering directories.
 */
#define ROOT_DIRECTORY 		(-1)

/**
 * The list with all command_t structs.
 */
static command_list_t console_commands;

/**
 * The layer id of the current command list.
 */
static int current_layer_id = ROOT_DIRECTORY;

/**
 * The current console prompt.
 */
static char console_prompt[PROMPT_MAX_CHARS+1] = DEFAULT_PROMPT;

/**
 * This is the command_t list used at the root directory.
 */
static command_t root_directory_commands[] = {
	{LAYER_LINK, 
			"link", 
			"Changes to link layer directory"}, 
	{LAYER_NET, 
			"net", 
			"Changes to net layer directory"},
	{LAYER_UNRELIABLE, 
			"unreliable", 
			"Changes to unreliable transport layer directory"},
	{LAYER_RELIABLE, 
			"reliable", 
			"Changes to reliable transport layer directory"}
};

/**
 * Constant used to indicate the number of commands that are at the root
 * directory.
 */
#define ROOT_DIRECTORY_SIZE (sizeof(root_directory_commands)/sizeof(command_t))

/*============================================================================*/
/* Private functions prototypes.                                              */
/*============================================================================*/

/**
 * Strip whitespace from the start and end of the string. 
 * After the last non-whitespace character will be put a '\0' character.
 * 
 * @param string - the string to be stripped.
 * @return a pointer inside the string argument indicating
 * 		where is the first non-whitespace character. 
 */
static char *strip_whitespaces(char *string);

/**
 * Duplicates a string. This function allocates the new string and return it.
 * So, dispose the returned string after it had been used.
 * 
 * @param s - string to be copied.
 * @return the duplicated string.
 */
static char *duplicate_string(char *s);

/**
 * Executes a command line. 
 * 
 * @param line - the string typed by the user. It has the command name and may
 * 		have arguments.
 * @return CONSOLE_OK if command was successfully executed. CONSOLE_ERROR if
 * 		the command name doesn't exists. CONSOLE_EXIT if the user had selected
 * 		the exit command.
 */
static int execute_line(char *line);

/**
 * Return a pointer to the command_t struct related to the command_name. Return
 * a NULL pointer if NAME isn't a registered command name. 
 * 
 * @param command_name - the name of the command to be looked up.
 * @return the command_t struct related to that command name.
 */
static command_t *find_command();

/**
 * Used for ReadLine API - Attempt to complete on the contents of text 
 * parameter.
 * 
 * @param start - start of rl_line_buffer that contains the word to complete.
 * @param end - end of rl_line_buffer that contains the word to complete.
 * @param text - is the word to complete.  
 * @return the array of matches, or NULL if there aren't any. 
 */
static char **console_completion(const char *text, int start, int end);

/**
 * Used for ReadLine API - Generator function for command completion.  
 * 
 * @param state - let us know whether to start from scratch; without any state
 * 		(i.e. state == 0), then we start at the top of the list. 
 * @return a completed command name if found, or NULL to determine that
 * 		there isn't any more similar commands.
 */
static char *command_generator(const char *text, int state);

/**
 * Loads the command_t array from a layer and place it at console_commands 
 * struct is. If some error occurs, the directory layer_directory_commands 
 * are loaded into the console_commands. The variables current_layer_id 
 * and console_prompt are updated according to the layer_id actually loaded.
 * 
 * @param layer_id - the layer to be requested.
 * @return the id of the layer current loaded.
 */
void load_commands(int layer_id); 

/**
 * Updates the console prompt, according to the current_layer_id variable.
 * See DEFAULT_PROMPT and PROMPT_FORMAT constants.
 */
void update_prompt();

/**
 * Handler for SIGPIPE signals.
 */
static void handler_SIGPIPE(int signal);

/*============================================================================*/
/* Public functions implementations.                                          */
/*============================================================================*/

void console_initialize() {
  	/* Allow conditional parsing of the ~/.inputrc file. */
  	rl_readline_name = READLINE_NAME;

  	/* Tell the completer that we want a crack first. */
  	rl_attempted_completion_function = console_completion;

	/* Override sigpipe handler. */
	signal(SIGPIPE, handler_SIGPIPE);

	/* Load directory commands. */
	load_commands(ROOT_DIRECTORY);
}
/******************************************************************************/
void console_loop() {
  	char *line, *s;
  	int result;
  	
  	while (1) {

      	line = readline(console_prompt);
    	if (!line) {
    		printf("\n");
    		/* EOF received. */
      		break;
      	}

      	/* 
      	 * Remove leading and trailing whitespace from the line.
         * Then, if there is anything left, add it to the history 
         * list and execute it. 
         */
      	s = strip_whitespaces(line);
      	if (*s) {
          	add_history(s);
          	result = execute_line(s);
         	if (result == CONSOLE_EXIT) {
          		return;
         	}
        }

		/* Dispose line read. */
      	free(line);
    }
}

/*============================================================================*/
/* Private functions implementations.                                         */
/*============================================================================*/

char *strip_whitespaces(char *string) {
  	register char *s, *t;

  	for (s = string; whitespace (*s); s++);
    
  	if (*s == 0) {
    	return s;
  	}

  	t = s + strlen (s) - 1;
  	while (t > s && whitespace (*t)) {
    	t--;
  	}
  	*++t = '\0';

  	return s;
}
/******************************************************************************/
int execute_line (char *line) {
  	register int i;
  	command_t *command;
  	char *command_name;
  	char *command_args;
  	int result;

  	/* command_name receives the first word of the line. */
  	i = 0;
  	while (line[i] && whitespace(line[i])) {
    	i++;
  	}
  	command_name = line + i;
  	while (line[i] && !whitespace(line[i])) {
    	i++;
  	}
  	if (line[i]) {
    	line[i++] = '\0';
  	}
  	
	/* If command is the exit command, we go back one directory or 
	 * finish execution in case we are at the root directory. */
	if (strcmp(command_name, EXIT_COMMAND_NAME) == 0) {
  		if (current_layer_id != ROOT_DIRECTORY) {
	  		/* Request new list of commands */
			load_commands(ROOT_DIRECTORY);
			return CONSOLE_OK;
  		} else {
			return CONSOLE_EXIT;
  		}
	}
	
  	/* Translate the command name to a command_t struct.
  	 * If the command doesn't exists, CONSOLE_ERROR is returned. */
  	command = find_command(command_name);
  	if (!command) {
      	fprintf (stderr, "%s: No such command.\n\n", command_name);
      	return CONSOLE_ERROR;
    }

  	/* command_args receives arguments, if any. */
  	while (whitespace(line[i])) {
    	i++;
  	}
  	command_args = line + i;
	
  	if (current_layer_id == ROOT_DIRECTORY) {
  		/* Request new list of commands */
		load_commands(command->id);
  	} else {
  		/* Request the execution of the command to the deamon. */
  		result = libconsole_send_command(current_layer_id, 
  				command->id, command_args);
  		if (result == LIBCONSOLE_COMMAND_ERROR) {
	  		/* Print the command help if the command fails. */
			printf("%s\n\n", command->doc);
  		} else if (result == LIBCONSOLE_ERROR) {
  			printf("Error sending command.\n");
  		}
  	}
  	
  	return CONSOLE_OK;
}
/******************************************************************************/
void load_commands(int layer_id) {
	current_layer_id = layer_id;
	
	/* Dispose command list if it is not the directory command */
	if (console_commands.list != root_directory_commands) {
		free(console_commands.list);
	}

	/* If requested layer_id is the layer directory, 
	 * return the directory command list. */
	if (current_layer_id == ROOT_DIRECTORY) {
		console_commands.list = root_directory_commands;
    	console_commands.size = ROOT_DIRECTORY_SIZE;
    	update_prompt();
    	return;
	}

	/* Try to load command. If error occurs we fall back 
	 * to LAYER_DIRECTORY, and return the directory command list. */
	if (libconsole_load_commands(&console_commands, current_layer_id) 
			== LIBCONSOLE_ERROR) {
		current_layer_id = ROOT_DIRECTORY;
		console_commands.list = root_directory_commands;
    	console_commands.size = ROOT_DIRECTORY_SIZE;
    	update_prompt();
    	fprintf(stderr, "error: Could not load commands.\n");
		return;
	}
	
   	update_prompt();
	return;
}
/******************************************************************************/
void update_prompt() {
	if (current_layer_id == ROOT_DIRECTORY) {
		strncpy(console_prompt, DEFAULT_PROMPT, PROMPT_MAX_CHARS);
	} else {
		/* Seek current directory name. */
		int i;
	  	for (i = 0; i < ROOT_DIRECTORY_SIZE; i++) {
	    	if (root_directory_commands[i].id == current_layer_id) {
	    		/* Directory found. Updating console prompt. */
				snprintf(console_prompt, PROMPT_MAX_CHARS, PROMPT_FORMAT, 
						root_directory_commands[i].name);
				return;
	    	}
	  	}
	  	
	  	/* Current directory missing. */
		snprintf(console_prompt, PROMPT_MAX_CHARS, PROMPT_FORMAT,"?");
	}
}
/******************************************************************************/
char *duplicate_string(char *s) {
  	char *r;
  	int string_length;
  	string_length = strlen(s);
  	r = malloc(string_length + 1);
  	strncpy(r, s, string_length + 1);
  	return r;
}
/******************************************************************************/
command_t *find_command(char *command_name) {
  	register int i;

  	for (i = 0; i<console_commands.size; i++) {
    	if (strcmp (command_name, console_commands.list[i].name) == 0) {
      		return (&console_commands.list[i]);
    	}
  	}

  	return ((command_t *)NULL);
}
/******************************************************************************/
char **console_completion (const char *text, int start, int end) {
  	char **matches;

  	matches = (char **)NULL;

  	/* If this word is at the start of the line, then it is a command
   	 * to complete.  Otherwise it is the name of a file in the current
   	 * directory. */
  	if (start == 0) {
		matches = rl_completion_matches (text, command_generator);
  	}

  	return (matches);
}
/******************************************************************************/
char *command_generator (const char *text, int state) {
  	static int list_index;
  	static int len;
  	char *name;

  	/* If this is a new word to complete, initialize it now.  This
     * includes saving the length of TEXT for efficiency, and
     * initializing the index variable to 0. */
  	if (!state) {
      	list_index = 0;
      	len = strlen (text);
    }

  	/* Return the next name which partially matches from the command list. */
  	while (list_index < console_commands.size){
  		name = console_commands.list[list_index].name;
      	list_index++;

      	if (strncmp (name, text, len) == 0) {
        	return (duplicate_string(name));
      	}
    }

	/* If this is the exit command, return it. */
   	if (list_index == console_commands.size) {
   		/* This will allow only one exit command. */
   		list_index++;
   		if (strncmp (text, EXIT_COMMAND_NAME, len) == 0) {
       		return (duplicate_string(EXIT_COMMAND_NAME));
   		}
   	}

  	/* If no names match, then return NULL. */
  	return ((char *)NULL);
} 	
/******************************************************************************/
void handler_SIGPIPE(int signal) {
	printf("SIGPIPE received.\n");
	/* Ignoring. This is necessary to handle the clients' disconnections. */
}
/******************************************************************************/
