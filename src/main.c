/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/main.c
 *
 * Description: Main Function
 *
 * ---------------------------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * ---------------------------------------------------------------------------
 */


/*****************************************************************************
 *
 * Headers
 *
 */

/* System headers */
#include <stdlib.h> /* NULL, malloc(), free()               */
#include <stdio.h>  /* puts(), fputs(), printf(), fprintf() */
#include <string.h> /* strcmp()                             */

/* Configuration */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

/* Local headers */
#include "structs.h"
#include "iptables.h"
#include "memory.h"


/*****************************************************************************
 *
 * Local Functions
 *
 */

/* Version string */
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "<unknown>"
#endif

/* Prototypes */
static void usage(const char *exe);

/*
 * Display the program usage help message
 */
static void usage(const char *const exe)
{
    /* Cut in two, because ISO C compilers are required to accept strings of
     * only 509 bytes at least */
    printf("Syntax: %s [options...] [files...]\n"
	   "\n"
	   "Available options:\n"
	   "    -c/--color:         use colors for the dump\n"
	   "    -d/--dump:          dump the configuration structures\n"
	   "    -e/--exe:           IPTables executable name (\"iptables\" by"
		   " default)\n"
	   "    -h/--help:          display this help message\n"
	   "    -i/--iptables:      generate an IPTables shellscript\n"
	   "    -n/--no-color:      don't use colors for the dump\n"
	   "    -o/--output <file>: output filename\n"
	   "    -v/--version:       display the program version\n"
	   "\n", exe);
    puts("You can specify any number of files in the command line, Use "
		 "\"-\" for the\n"
	 "standard input as long as chain names are all different.  If no "
		 "filename is\n"
	 "given, the standard input is read.\n"
	 "\n"
	 "If an option is given more than once, the last one takes "
		 "precedence.\n"
	 "\n"
	 "Note about colors: by default, colors are used if the IPTables "
		 "script isn't\n"
	 "generated.  This is not to \"corrupt\" the script if it is "
		 "edited.\n"
	 "\n"
	 "Thank you for using RuleWall!");
}


/*****************************************************************************
 *
 * Global Functions
 *
 */

/* Defined in parser.y */
extern struct chain *parse_config(const char *const filename);

/*
 * Main function
 */
int main(const int argc, const char *const *const argv)
{
    /* Files and generated config */
    const char **const files
	    = malloc(sizeof(char *) * (argc > 1 ? argc - 1 : 1));
    unsigned nb_files = 0;
    const char *out_file = NULL;
    FILE *output;
    struct chain *config, *last;
    const char *exe = "iptables";

    /* Command line options */
    enum {
	COLORS_DEFAULT, COLORS_FALSE, COLORS_TRUE
    } use_colors = COLORS_DEFAULT;
    enum bool do_dump = FALSE, do_iptables = FALSE, do_usage = FALSE;
    enum bool do_version = FALSE, do_output = FALSE, do_exe = FALSE;

    /* Counters */
    unsigned i, j;

    if (files == NULL) {
	fputs("Not enough memory! Aborting.\n", stderr);
	return 10;
    }

    /* Parse options */
    for (i = 1; i < (unsigned) argc; i++) {
	if (do_output == TRUE) {
	    do_output = FALSE;
	    out_file = argv[i];
	} else if (do_exe == TRUE) {
	    do_exe = FALSE;
	    exe = argv[i];
	} else if (argv[i][0] == '-') {
	    if (argv[i][1] == '-') {
		if (strcmp(argv[i] + 2, "color") == 0)
		    use_colors = COLORS_TRUE;
		else if (strcmp(argv[i] + 2, "dump") == 0)
		    do_dump = COLORS_TRUE;
		else if (strcmp(argv[i] + 2, "exe") == 0)
		    do_exe = TRUE;
		else if (strcmp(argv[i] + 2, "help") == 0)
		    do_usage = TRUE;
		else if (strcmp(argv[i] + 2, "iptables") == 0)
		    do_iptables = TRUE;
		else if (strcmp(argv[i] + 2, "no-color") == 0)
		    use_colors = COLORS_FALSE;
		else if (strcmp(argv[i] + 2, "output") == 0)
		    do_output = TRUE;
		else if (strcmp(argv[i] + 2, "version") == 0)
		    do_version = TRUE;
		else {
		    fprintf(stderr, "Error: invalid option \"%s\".\n"
			    "Use -h or --help for a full list.\n",
			    argv[i]);
		    return 1;
		}
	    } else {
		for (j = 1; argv[i][j] != '\0'; j++)
		    switch (argv[i][j]) {
		    case 'c':
			use_colors = COLORS_TRUE;
			break;

		    case 'd':
			do_dump = TRUE;
			break;

		    case 'e':
			if (do_output == TRUE) {
			    fputs("Error: cannot use \"-e\" and \"-o\" at the"
				  " same time.\n", stderr);
			    return 2;
			}
			do_exe = TRUE;
			break;

		    case 'h':
			do_usage = TRUE;
			break;

		    case 'i':
			do_iptables = TRUE;
			break;

		    case 'n':
			use_colors = COLORS_FALSE;
			break;

		    case 'o':
			if (do_exe == TRUE) {
			    fputs("Error: cannot use \"-e\" and \"-o\" at the"
				  " same time.\n", stderr);
			    return 2;
			}
			do_output = TRUE;
			break;

		    case 'v':
			do_version = TRUE;
			break;

		    default:
			fprintf(stderr, "Error: invalid option \"-%c\".\n"
				"Use -h or --help for a full list.\n",
				argv[i][j]);
			return 1;
		    }
	    }
	} else
	    files[nb_files++] = argv[i];
    }

    /* If help message is requested */
    if (do_usage == TRUE) {
	usage(argv[0]);
	return 0;
    }

    /* If version is requested */
    if (do_version == TRUE) {
	puts("RuleWall version " PACKAGE_VERSION "\n"
	     "Copyright (C) 2006 Benjamin Gaillard\n"
	     "This program is covered by the GPL licence version 2");
	return 0;
    }

    /* Check is at least one action has been given */
    if (do_dump == FALSE && do_iptables == FALSE) {
	fputs("Error: no action selected.  Use -d/--dump and/or "
	      "-i/--iptables, or -h/--help\nfor a full list of options.\n",
	      stderr);
	return 2;
    }

    /* Check for output file */
    if (do_output == TRUE) {
	fputs("Error: -o/--output option used, but no file specified.\n",
	      stderr);
	return 2;
    }
    if (out_file == NULL || (out_file[0] == '-' && out_file[1] == '\0'))
	output = stdout;
    else if ((output = fopen(out_file, "w")) == NULL) {
	fprintf(stderr, "Error: cannot write to file \"%s\": ", out_file);
	perror(NULL);
	return 3;
    }

    /* Enable colors if desired */
    if (use_colors == COLORS_DEFAULT)
	use_colors = do_iptables ? COLORS_FALSE : COLORS_TRUE;

    /* Parse files */
    if (nb_files == 0) {
	/* If no file was given, use standard input */
	files[0] = "-";
	nb_files = 1;
    }
    if ((last = config = parse_config(files[0])) == NULL)
	return 4;
    for (i = 1; i < nb_files; i++) {
	/* Look for the last chain */
	while (last->next != NULL)
	    last = last->next;

	/* Append the new read chains to the list */
	if ((last->next = parse_config(files[i])) == NULL)
	    return 4;
    }

    /* Free some memory */
    free(files);

    /* Header, for IPTables script */
    if (do_iptables == TRUE) {
	fputs("#!/bin/sh\n\n"
	      "# This script has been generated by RuleWall.\n\n", output);
	if (do_dump == TRUE) {
	    fputs("# Here is a dump of the full configuration:\n#\n", output);
	}
    }

    /* Dump */
    if (do_dump == TRUE)
	dump_config(config, output, do_iptables == TRUE ? "# " : NULL,
		    !do_iptables, use_colors == COLORS_TRUE ? TRUE : FALSE);

    /* Create IPTables script */
    if (do_iptables == TRUE)
	ipt_config(config, exe, output);

    /* Close files and free all this stuff */
    fclose(output);
    free_chain(config);

    /* Check memory allocation */
    if (mem_get_count() != 0)
	fprintf(stderr, "Warning: %u remaining memory areas (not freed)!\n",
		mem_get_count());

    /* Finally, it's done! */
    return 0;
}

/* End of File */
