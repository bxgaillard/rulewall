/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/lexer.l
 *
 * Description: Lex/Flex Lexer
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


%{

/*****************************************************************************
 *
 * Headers
 *
 */

/* ./configure result */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif /* HAVE_CONFIG_H */

/* System headers */
#include <stdlib.h> /* NULL, malloc(), free(), atoi() */
#include <stdio.h>  /* fopen(), fclose(), printf() */
#include <string.h> /* strlen(), strdup(), strrchr(), strcpy(), memcpy() */
#if CHECK_PORT_NAMES
#include <netdb.h> /* getservbyname() */
#endif /* CHECK_PORT_NAMES */

/* Local headers */
#include "structs.h"
#include "memory.h"
#include "parser.h"


/*****************************************************************************
 *
 * Local Variables
 *
 */

/* State values */
static enum bool is_list;       /* Wether a host/port belongs to a list    */
static enum proto cur_proto;    /* Current protocol (ip, tcp, udp)         */
static enum direction is_dired; /* Wether the direction has beed specified */

/* Current state */
static enum {
    STATE_INIT, STATE_INCL, STATE_CHAIN, STATE_HOSTS, STATE_PORTS
} state;

/* File context structure */
struct context {
    struct context *prev;   /* Previous context    */
    FILE *file;             /* File descriptor     */
    char *name;             /* Filename            */
    int cur_line;           /* Current line number */
    YY_BUFFER_STATE buffer; /* Lex buffer          */
};

/* Current file context */
static struct context *cur_context = NULL;


/*****************************************************************************
 *
 * Local functions
 *
 */

/* Functions defined at the end of this file */
extern enum bool begin_file(const char *name);
extern enum bool end_file(void);

/* The first element of the chain linked list */
extern struct chain *config; /* Defined in parser.y */

/*
 * Find a chain structure corresponding to its associated name
 */
static const struct chain *find_chain(const char *const name)
{
    const struct chain *chain;

    /* Here we search throughout the list; we could have implemented a hash
     * table or something like that, but it's time-consuming and it goes far
     * beyond the scope of this project. */
    for (chain = config; chain != NULL; chain = chain->next)
	if (strcmp(chain->name, name) == 0)
	    return chain;

    /* Not found */
    return NULL;
}

%}


/*****************************************************************************
 *
 * Lex/Flex Options and Subexpressions
 *
 */

/* Flex-specific options */
%option nointeractive
%option noyywrap noinput nounput
%option noyy_push_state noyy_pop_state noyy_top_state
%option noyy_scan_buffer noyy_scan_bytes noyy_scan_string


/*
 * Additional states
 */

/* C-style comment */
%x COMMENT

/* Chain definition and include */
%x CHAIN INCL

/* Host, host list, port and port list */
%x HOSTS PORTS


/*
 * Subexpressions (for simpler expressions below)
 */

/* Whitespace */
SPACE [ \t\n\r]

/* Decimal byte (0-255) */
BYTE 25[0-5]|2[0-4][0-9]|([01]?[0-9])?[0-9]

/* IPv4 address */
IPV4 ({BYTE}\.){3}{BYTE}

/* IPv4 address mask */
MASK \/({IPV4}|3[0-2]|[0-2]?[0-9])

/* IPv6 address */
IPV6 ([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}

%%


 /****************************************************************************
  *
  * Symbols Definitions
  *
  */

 /*
  * Comments
  */

 /* C++- and shell-style comments */
<*>("//"|#).*\n cur_context->cur_line++;

 /* C-style comments */

 /* State-changing start of comment */
"/*"        { state = STATE_INIT;  BEGIN(COMMENT); }
<INCL>"/*"  { state = STATE_INCL;  BEGIN(COMMENT); }
<CHAIN>"/*" { state = STATE_CHAIN; BEGIN(COMMENT); }
<HOSTS>"/*" { state = STATE_HOSTS; BEGIN(COMMENT); }
<PORTS>"/*" { state = STATE_PORTS; BEGIN(COMMENT); }
<COMMENT>{
    [^*]*|\*+[^*/]* { /* Eat up the content of a comment */
	int i;
	for (i = 0; yytext[i] != '\0'; i++)
	    if (yytext[i] == '\n')
		cur_context->cur_line++;
    }

    \*+\/ { /* End of comment */
	switch (state) {
	case STATE_INCL:
	    BEGIN(INCL);
	    break;

	case STATE_CHAIN:
	    BEGIN(CHAIN);
	    break;

	case STATE_HOSTS:
	    BEGIN(HOSTS);
	    break;

	case STATE_PORTS:
	    BEGIN(PORTS);
	    break;

	default:
	    BEGIN(INITIAL);
	}
    }
}


 /*
  * Include State
  */

 /* Include keyword */
include/{SPACE} BEGIN(INCL);

 /* Filename */
<INCL>{
    \"[^"\n]*(\\\"[^"\n]*)*\" {
	yytext[strlen(yytext) - 1] = '\0';
	begin_file(yytext + 1);
	BEGIN(INITIAL);
    }

    [^ \t\n\r]+ {
	begin_file(yytext);
	BEGIN(INITIAL);
    }
}


 /*
  * Initial (Global) State
  */

 /* Chain operators */
<CHAIN>{
    ; { BEGIN(INITIAL); return CHAINSEP; } /* Chain separator   */
    =                   return ASSIGN;     /* Chain assignation */
}

 /* Condition operands */
<CHAIN>{
    !    return OP_NOT;
    &&   return OP_AND;
    "||" return OP_OR;
    \(   return PAR_OPEN;
    \)   return PAR_CLOSE;
}

 /* Final (predefined) chains: ACCEPT, DROP, REJECT */
<CHAIN>{
    (ACCEPT|accept)/[ \t\n\r;] { yylval.final_val = FINAL_ACCEPT;
				 return FINAL; }
    (DROP|drop)/[ \t\n\r;]     { yylval.final_val = FINAL_DROP;
				 return FINAL; }
    (REJECT|reject)/[ \t\n\r;] { yylval.final_val = FINAL_REJECT;
				 return FINAL; }
}

 /* if/then/else keywords */
<CHAIN>{
    if/[ \t\n\r!(] return IF;
    then/{SPACE}   return THEN;
    else/{SPACE}   return ELSE;
}

 /* Network (IP) and transport (TCP, UDP) protocols identifiers */
<CHAIN>{
    ip/{SPACE}   { BEGIN(HOSTS); is_list = FALSE; is_dired = FALSE;
		   cur_proto = yylval.proto_val = PROTO_IP;   return IP;    }
    ipv4/{SPACE} { BEGIN(HOSTS); is_list = FALSE; is_dired = FALSE;
		   cur_proto = yylval.proto_val = PROTO_IPV4; return IP;    }
    ipv6/{SPACE} { BEGIN(HOSTS); is_list = FALSE; is_dired = FALSE;
		   cur_proto = yylval.proto_val = PROTO_IPV6; return IP;    }
    port/{SPACE} { BEGIN(PORTS); is_list = FALSE; is_dired = FALSE;
		   cur_proto = yylval.proto_val = PROTO_PORT; return PROTO; }
    udp/{SPACE}  { BEGIN(PORTS); is_list = FALSE; is_dired = FALSE;
		   cur_proto = yylval.proto_val = PROTO_UDP;  return PROTO; }
    tcp/{SPACE}  { BEGIN(PORTS); is_list = FALSE; is_dired = FALSE;
		   cur_proto = yylval.proto_val = PROTO_TCP;  return PROTO; }
}

 /* Chain identifier */
<INITIAL,CHAIN>[A-Za-z_-][A-Za-z0-9_-]* {
    char *name;
    const struct chain *chain;

    /* Names beginning with "__" are reserved for internal usage */
    if (yytext[0] == '_' && yytext[1] == '_')
	return INVALID;

    /* Save name in memory */
    name = mem_strdup(yytext);

    /* Check if the chain already exists */
    if ((chain = find_chain(name)) != NULL) {
	yylval.chain_cval = chain;
	return USERCHAIN;
    }

    BEGIN(CHAIN);
    yylval.string = name;
    return NEWCHAIN;
}


 /*
  * Host and Port State
  */

 /* Direction: source or destination */
<HOSTS,PORTS>{
    (source|src)/[ \t\n\r{] { /* Source */
#define MAKE_DIR(dir)               \
    if (is_dired) {                 \
	if (cur_proto < PROTO_PORT) \
	    goto jump_host;         \
	goto jump_port;             \
    }                               \
				    \
    is_dired = TRUE;                \
    yylval.dir_val = dir;           \
    return DIRECTION;

	MAKE_DIR(DIR_SRC)
    }

    (destination|dst)/[ \t\n\r{] { /* Destination */
	MAKE_DIR(DIR_DST)
    }

    both/[ \t\n\r{] { /* Both ways */
	MAKE_DIR(DIR_BOTH)
    }
}

 /* List operators */
<HOSTS,PORTS>{
    \{ { is_dired = TRUE; is_list = TRUE; return LIST_BEGIN; } /* Beginning */
    \} { is_dired = TRUE; BEGIN(CHAIN);   return LIST_END;   } /* End       */
    ,  { is_dired = TRUE;                 return LIST_SEP;   } /* Separator */
}

 /* Numeric IPv4 address or machine name, with possible mask */
<HOSTS>({IPV4}|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*){MASK}? {
jump_host:
    is_dired = TRUE;

    /* Save name in memory */
    if (is_list == FALSE)
	BEGIN(CHAIN);
    yylval.string = mem_strdup(yytext);
    return ADDR;
}

<PORTS>{
    [0-9]{1,5}(-[0-9]{1,5})? { /* Numeric port number/range */
	char *second = strchr(yytext, '-');
	int port;

	is_dired = TRUE;

	/* Separe the two numbers in case of a range */
	if (second != NULL)
	    *second++ = '\0';

	/* Get the first number and check it */
	port = atoi(yytext);
	if ((port & ~0xFFFF) != 0)
	    return INVALID;
	yylval.port_val.from = (unsigned short) port;

	/* Get the second number and check it */
	if (second == NULL)
	    /* Same as first number */
	    yylval.port_val.to = (unsigned short) port;
	else {
	    /* Second part of the string */
	    port = atoi(second);
	    if ((port & ~0xFFFF) != 0)
		return INVALID;
	    yylval.port_val.to = (unsigned short) port;
	}

	/* If not in a list, it's done */
	if (is_list == FALSE)
	    BEGIN(CHAIN);
	return PORT;
    }

    [A-Za-z0-9_-]+ { /* Port service name */
    jump_port:
	is_dired = TRUE;

#if CHECK_PORT_NAMES
	/* Verify port name for existence */

	/* Note: it isn't specified in the manual page wether this function
	 * returns a dynamically allocated (malloc()'ed) structure; I suppose
	 * it doesn't, hence there's no free()... */
	if (getservbyname(yytext, proto_name[cur_proto]) == NULL)
	    return INVALID;
#endif

	/* If not in a list, it's done */
	if (is_list == FALSE)
	    BEGIN(CHAIN);
	yylval.string = mem_strdup(yytext);
	return PORTNAME;
    }
}


 /*
  * Whitespace and Invalid Characters
  */

 /* Count end of lines for line numbering facility */
<*>\r\n?|\n\r? cur_context->cur_line++;

 /* Ignore space characters */
<*>[ \t]+ ;

 /* Everything not catched yet is considered invalid */
<*>[A-Za-z0-9_.-]+|. return INVALID;

 /* End of file */
<<EOF>> {
    if (end_file() == FALSE)
	return EOF;
}

%%


/*****************************************************************************
 *
 * Local Functions
 *
 */

/*
 * Build a full filename relative to a reference
 */
static char *make_rel_name(const char *const ref, const char *const name)
{
    const char *file;
    unsigned dirlen;
    char *res;

    /* If absolute or reference has no directory part, it remains the same */
    if (name[0] == '/' || (file = strrchr(ref, '/')) == NULL)
	return strdup(name);

    /* Get the directory length */
    dirlen = (unsigned) ((unsigned long) file - (unsigned long) ref);

    /* Make the filename */
    if ((res = malloc(dirlen + strlen(name) + 2)) != NULL) {
	memcpy(res, ref, dirlen);
	res[dirlen] = '/';
	strcpy(res + dirlen + 1, name);
    }

    return res;
}

/*
 * Begin the processing of a new (included) file
 */
enum bool begin_file(const char *name)
{
    struct context *cont;

    if ((cont = malloc(sizeof(struct context))) == NULL)
	return FALSE;
    if (name == NULL || (name[0] == '-' && name[1] == '\0')) {
	/* Standard input */
	cont->file = stdin;
	cont->buffer = YY_CURRENT_BUFFER;
	cont->name = NULL;
    } else {
	/* Get a correct path */
	if (cur_context != NULL && cur_context->name != NULL)
	    cont->name = make_rel_name(cur_context->name, name);
	else
	    cont->name = strdup(name);

	/* Given file */
	if ((cont->file = fopen(cont->name, "r")) == NULL) {
	    fprintf(stderr, "Error: could not open \"%s\": ", cont->name);
	    perror(NULL);
	    free(cont);
	    return FALSE;
	}
	if ((cont->buffer = yy_create_buffer(cont->file, YY_BUF_SIZE))
		    == NULL) {
	    fclose(cont->file);
	    free(cont);
	    return FALSE;
	}
	yy_switch_to_buffer(cont->buffer);
    }

    /* Initialize structure */
    cont->prev = cur_context;
    cont->cur_line = 1;
    cur_context = cont;

    return TRUE;
}

/*
 * End the processing of the current file and return back to the previous one
 */
enum bool end_file(void)
{
    struct context *prev;

    /* Check if it isn't already the last one */
    if (cur_context == NULL)
	return FALSE;
    prev = cur_context->prev;

    /* Switch back to the previous buffer */
    if (prev != NULL && prev->buffer != NULL)
	yy_switch_to_buffer(prev->buffer);
    if (cur_context->buffer != NULL)
	yy_delete_buffer(cur_context->buffer);

    /* Free file and memory */
    fclose(cur_context->file);
    free(cur_context->name);
    free(cur_context);

    /* Update the current pointer */
    if ((cur_context = prev) == NULL)
	return FALSE;
    return TRUE;
}

/*
 * Get the current line number
 */
unsigned get_line(void)
{
    return cur_context->cur_line;
}

/*
 * Get the current file name
 */
const char *get_file(void)
{
    return cur_context->name;
}

/* End of File */
