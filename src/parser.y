/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/parser.y
 *
 * Description: Yacc Parser
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

#include <stdlib.h> /* NULL, malloc(), free() */
#include <stdio.h>

#include "structs.h"
#include "memory.h"

/* The first defined chain */
struct chain *config;


/*****************************************************************************
 *
 * Yacc Functions
 *
 */

/* Yacc needs yylex() to be defined */
extern int yylex(void);

/* Yacc needs this... */
#ifdef __GNUC__
#define UNUSED __attribute__((__unused__))
#else
#define UNUSED
#endif
static void yyerror(char *string UNUSED)
{}

%}

/* The union used to return values from symbols */
%union {
    struct chain       *chain_val;     /* Chain          */
    const struct chain *chain_cval;    /* Constant chain */
    struct action      *action_val;    /* Action         */
    struct test        *test_val;      /* Test           */
    struct expr        *expr_val;      /* Expression     */
    struct condition   *condition_val; /* Condition      */
    struct addr        *addrs_val;     /* Addresses      */
    struct port        *ports_val;     /* Ports          */
    enum final          final_val;     /* Final action   */
    enum proto          proto_val;     /* Protocol       */
    enum direction      dir_val;       /* Direction      */
    struct one_port     port_val;      /* Just one port  */
    char               *string;        /* Simple string  */
}

/* Non terminal symbols */
%type <chain_val> configuration chain
%type <action_val> action
%type <test_val> test
%type <expr_val> expr
%type <condition_val> condition
%type <dir_val> direction
%type <addrs_val> addrs addrlist addr
%type <ports_val> ports portlist port

/* Chain definition symbols */
%token CHAINSEP
%token ASSIGN
%token <final_val> FINAL
%token <string> NEWCHAIN
%token <chain_cval> USERCHAIN

/* if/then/else keywords */
%token IF THEN ELSE

/* Condition operands */
%token PAR_OPEN PAR_CLOSE
%left OP_OR
%left OP_AND
%nonassoc OP_NOT

/* Protocol-related tokens */
%token <proto_val> IP PROTO
%token <dir_val> DIRECTION

/* List operators */
%token LIST_BEGIN LIST_END
%token LIST_SEP

/* Port-related tokens */
%token <port_val> PORT
%token <string> PORTNAME

/* A simple malloc()'ed string, returned by several terminal symbols */
%token <string> ADDR

/* Invalid token */
%token INVALID

/* Start symbol */
%start configuration

%%


/*****************************************************************************
 *
 * Yacc Rules
 *
 */

/* A configuration: a chain ensemble */
configuration:
    chain configuration {
	$1->next = $2;
	$$ = $1;
    } | chain {
	$$ = $1;
    };

/* A chain definition */
chain:
    NEWCHAIN ASSIGN action CHAINSEP {
	if (($$ = mem_alloc(sizeof(struct chain))) != NULL) {
	    $$->next = NULL;
	    $$->name = $1;
	    $$->action = $3;

	    if (config == NULL)
		config = $$;
	}
    };

/* An action : final, user or conditional (test) */
action:
    FINAL {
	/* Pre-defined final action chain */
	if (($$ = mem_alloc(sizeof(struct action))) != NULL) {
	    $$->type = TARGET_FINAL;
	    $$->action.final = $1;
	}
    } | USERCHAIN { /* Extension */
	/* User-defined action chain */
	if (($$ = mem_alloc(sizeof(struct action))) != NULL) {
	    $$->type = TARGET_USER;
	    $$->action.user = $1;
	}
    } | test {
	/* Conditional actions */
	if (($$ = mem_alloc(sizeof(struct action))) != NULL) {
	    $$->type = TARGET_TEST;
	    $$->action.test = $1;
	}
    };

/* An if/then/else test */
test:
    IF expr test_then action ELSE action {
	if (($$ = mem_alloc(sizeof(struct test))) != NULL) {
	    $$->expr = $2;
	    $$->act_then = $4;
	    $$->act_else = $6;
	}
    };
test_then: THEN | ;

/* A test expression */
expr:
    OP_NOT expr {
	$2->not = !$2->not;
	$$ = $2;
    } | PAR_OPEN expr PAR_CLOSE {
	$$ = $2;
    } | expr OP_AND expr {
	if (($$ = mem_alloc(sizeof(struct expr))) != NULL) {
	    $$->not = FALSE;
	    $$->type = EXPR_AND;
	    $$->sub.expr.left = $1;
	    $$->sub.expr.right = $3;
	}
    } | expr OP_OR expr {
	if (($$ = mem_alloc(sizeof(struct expr))) != NULL) {
	    $$->not = FALSE;
	    $$->type = EXPR_OR;
	    $$->sub.expr.left = $1;
	    $$->sub.expr.right = $3;
	}
    } | condition {
	if (($$ = mem_alloc(sizeof(struct expr))) != NULL) {
	    $$->not = FALSE;
	    $$->type = EXPR_COND;
	    $$->sub.cond = $1;
	}
    };

/* A simple condition */
condition:
    IP direction addrs {
	if (($$ = mem_alloc(sizeof(struct condition))) != NULL) {
	    $$->type = COND_ADDR;
	    $$->proto = $1;
	    $$->dir = $2;
	    $$->cond.addr = $3;
	}
    } | PROTO direction ports {
	if (($$ = mem_alloc(sizeof(struct condition))) != NULL) {
	    $$->type = COND_PORT;
	    $$->proto = $1;
	    $$->dir = $2;
	    $$->cond.port = $3;
	}
    };

/* A packet direction */
direction:
    DIRECTION {
	$$ = $1;
    } | {
	$$ = DIR_BOTH;
    };

/* Either a single address or an address list */
addrs:
    addr {
	$1->next = NULL;
	$$ = $1;
    } | LIST_BEGIN addrlist LIST_END {
	$$ = $2;
    };

/* An address list */
addrlist:
    addr LIST_SEP addrlist {
	$1->next = $3;
	$$ = $1;
    } | addr {
	$1->next = NULL;
	$$ = $1;
    };

/* One address */
addr:
    ADDR {
	if (($$ = mem_alloc(sizeof(struct addr))) != NULL) {
	    $$->string = $1;
	}
    };

/* Either a single port or a port list */
ports:
    port {
	$1->next = NULL;
	$$ = $1;
    } | LIST_BEGIN portlist LIST_END {
	$$ = $2;
    };

/* A port list */
portlist:
    port LIST_SEP portlist {
	$1->next = $3;
	$$ = $1;
    } | port {
	$1->next = NULL;
	$$ = $1;
    };

/* One port */
port:
    PORT {
	if (($$ = mem_alloc(sizeof(struct port))) != NULL) {
	    $$->type = PORT_NUMERIC;
	    $$->port.range = $1;
	}
    } | PORTNAME {
	if (($$ = mem_alloc(sizeof(struct port))) != NULL) {
	    $$->type = PORT_NAME;
	    $$->port.name = $1;
	}
    };

%%


/*****************************************************************************
 *
 * Additional Functions
 *
 */

/* Lex text buffer, defined in lexer.l */
extern char *yytext;

/* Extern functions defined in lexer.l */
extern enum bool begin_file(const char *name);
extern const char *get_file(void);
extern unsigned get_line(void);

/*
 * Parse a configuration file, or standard input if filename is NULL
 */
struct chain *parse_config(const char *const filename)
{
    if (begin_file(filename) == FALSE)
	return NULL;

    /* Initialize variables */
    config = NULL;

    /* Parse input/file */
    if (yyparse() != 0) {
	fprintf(stderr,
		"Parsing error: file \"%s\", line %d, near \"%s\".\n",
		get_file(), get_line(), yytext);
	mem_free_all();
	return NULL;
    }

    return config;
}

/* End of File */
