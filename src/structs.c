/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/structs.c
 *
 * Description: Structure Dunping and Freeing Functions
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
#include <stdlib.h> /* NULL, free()               */
#include <string.h> /* strcmp()                   */
#include <stdio.h>  /* putc(), fputs(), fprintf() */

/* Local headers */
#include "memory.h"
#include "structs.h"


/*****************************************************************************
 *
 * Constants and Macros
 *
 */

/* Number of spaces used for the indentation in the dumps */
#define INDENT_SPACES 2

/* Macros used to make a color string */
#define MAKE_STRING(string)  MAKE_STRING2(string)
#define MAKE_STRING2(string) #string
#define MAKE_COLOR(number)   "\033[" MAKE_STRING(number) ";1m"

/* Color strings */
#define COLOR_RESET   "\033[0m"
#define COLOR_SILVER  "\033[37m"
#define COLOR_GRAY    MAKE_COLOR(30)
#define COLOR_RED     MAKE_COLOR(31)
#define COLOR_GREEN   MAKE_COLOR(32)
#define COLOR_YELLOW  MAKE_COLOR(33)
#define COLOR_BLUE    MAKE_COLOR(34)
#define COLOR_MAGENTA MAKE_COLOR(35)
#define COLOR_CYAN    MAKE_COLOR(36)
#define COLOR_WHITE   MAKE_COLOR(37)

/* Colors for language elements */
#define COLOR_COMMENT  COLOR_SILVER
#define COLOR_CHAIN    COLOR_CYAN
#define COLOR_OPERATOR COLOR_WHITE
#define COLOR_KEYWORD  COLOR_YELLOW
#define COLOR_FINAL    COLOR_MAGENTA
#define COLOR_PROTO    COLOR_GREEN
#define COLOR_DIR      COLOR_RED
#define COLOR_HOST     COLOR_BLUE
#define COLOR_PORT     COLOR_BLUE

/* Macro to simplify conditional use of colors ("CD" for "Color Display") */
#define CD(with, without) (use_colors ? (with) : (without))


/*****************************************************************************
 *
 * Freeing Functions
 *
 */

/*
 * Free a chain structure
 */
void free_chain(struct chain *chain)
{
    if (chain == NULL)
	return;

    free_chain(chain->next);
    mem_free(chain->name);
    free_action(chain->action);

    mem_free(chain);
}

/*
 * Free an action structure
 */
void free_action(struct action *action)
{
    if (action == NULL)
	return;

    if (action->type == TARGET_TEST)
	free_test(action->action.test);

    mem_free(action);
}

/*
 * Free a test structure
 */
void free_test(struct test *test)
{
    if (test == NULL)
	return;

    free_expr(test->expr);
    free_action(test->act_then);
    free_action(test->act_else);

    mem_free(test);
}

/*
 * Free an expr structure
 */
void free_expr(struct expr *expr)
{
    if (expr == NULL)
	return;

    if (expr->type == EXPR_COND) {
	free_condition(expr->sub.cond);
    } else {
	free_expr(expr->sub.expr.left);
	free_expr(expr->sub.expr.right);
    }

    mem_free(expr);
}

/*
 * Free a condition structure
 */
void free_condition(struct condition *condition)
{
    if (condition == NULL)
	return;

    switch (condition->type) {
    case COND_ADDR:
	free_addr(condition->cond.addr);
	break;

    case COND_PORT:
	free_port(condition->cond.port);
    }

    mem_free(condition);
}

/*
 * Free an addr structure
 */
void free_addr(struct addr *addr)
{
    if (addr == NULL)
	return;

    free_addr(addr->next);
    mem_free(addr->string);

    mem_free(addr);
}

/*
 * Free a port structure
 */
void free_port(struct port *port)
{
    if (port == NULL)
	return;

    free_port(port->next);
    if (port->type == PORT_NAME)
	mem_free(port->port.name);

    mem_free(port);
}


/*****************************************************************************
 *
 * Dumping Functions
 *
 */

/* Local functions */
static void dump_chain(const struct chain *chain, unsigned depth);
static void dump_action(const struct action *action, unsigned depth);
static void dump_test(const struct test *test, unsigned depth);
static void dump_test_2(const struct test *test, unsigned depth);
static void dump_expr(const struct expr *expr, unsigned depth);
static void dump_condition(const struct condition *condition);
static void dump_addr(const struct addr *addr);
static void dump_one_addr(const struct addr *addr);
static void dump_port(const struct port *port);
static void dump_one_port(const struct port *port);

/* Local variables */
static FILE *out_file;          /* The file where tu output the dump    */
static const char *line_prefix; /* What to display in front of lines    */
static enum bool use_colors;    /* Wether to display the dump in colors */

/*
 * Prefix and indent an output line
 */
static void indent(unsigned depth)
{
    fputs(line_prefix, out_file);

    depth *= INDENT_SPACES;
    while (depth-- != 0)
	putc(' ', out_file);
}

/*
 * Dump a full configuration
 */
void dump_config(const struct chain *chain, FILE *const file,
		 const char *const prefix, const enum bool comment,
		 const enum bool colors)
{
    out_file = file == NULL ? stdout : file;
    line_prefix = prefix == NULL ? "" : prefix;
    use_colors = colors;

    if (comment) {
	indent(0U);
	fputs(CD(COLOR_COMMENT "// Configuration dump generated by RuleWall"
		 COLOR_RESET "\n", "// Configuration dump generated by "
		 "RuleWall\n"), out_file);
	indent(0U);
	putc('\n', out_file);
    }

    dump_chain(chain, 0U);
    while ((chain = chain->next) != NULL) {
	indent(0U);
	putc('\n', out_file);
	dump_chain(chain, 0U);
    }

    out_file = stdout;
    line_prefix = "";
    use_colors = FALSE;
}

/*
 * Dump a chain structure
 */
static void dump_chain(const struct chain *const chain, const unsigned depth)
{
    indent(depth);
    fprintf(out_file, CD(COLOR_CHAIN "%s" COLOR_RESET " "
			 COLOR_OPERATOR "=" COLOR_RESET "\n", "%s =\n"),
	    chain->name);

    dump_action(chain->action, depth + 1);
    indent(depth);
    fputs(CD(COLOR_OPERATOR ";" COLOR_RESET "\n", ";\n"), out_file);
}

/*
 * Dump an action structure
 */
static void dump_action(const struct action *const action,
			const unsigned depth)
{
    switch (action->type) {
    case TARGET_FINAL:
	indent(depth);
	switch (action->action.final) {
	case FINAL_ACCEPT:
	    fputs(CD(COLOR_FINAL "accept" COLOR_RESET "\n", "accept\n"),
		  out_file);
	    break;

	case FINAL_DROP:
	    fputs(CD(COLOR_FINAL "drop" COLOR_RESET "\n", "drop\n"),
		  out_file);
	    break;

	case FINAL_REJECT:
	    fputs(CD(COLOR_FINAL "reject" COLOR_RESET "\n", "reject\n"),
		  out_file);
	}
	break;

    case TARGET_USER:
	indent(depth);
	fprintf(out_file, CD(COLOR_CHAIN "%s" COLOR_RESET "\n", "%s\n"),
		action->action.user->name);
	break;

    case TARGET_TEST:
	dump_test(action->action.test, depth);
    }
}

/*
 * Dump a test structure
 */
static void dump_test(const struct test *const test, const unsigned depth)
{
    indent(depth);
    dump_test_2(test, depth);
}

/*
 * Dump a test structure, without indenting the first "if" (used to dieplay
 * "else if" on a single line)
 */
static void dump_test_2(const struct test *const test, const unsigned depth)
{
    fputs(CD(COLOR_KEYWORD "if" COLOR_RESET "\n", "if\n"), out_file);
    dump_expr(test->expr, depth + 1);

    indent(depth);
    fputs(CD(COLOR_KEYWORD "then" COLOR_RESET "\n", "then\n"), out_file);
    dump_action(test->act_then, depth + 1);

    indent(depth);
    fputs(CD(COLOR_KEYWORD "else" COLOR_RESET, "else"), out_file);
    if (test->act_else->type == TARGET_TEST) {
	putc(' ', out_file);
	dump_test_2(test->act_else->action.test, depth);
    } else {
	putc('\n', out_file);
	dump_action(test->act_else, depth + 1);
    }
}

/*
 * Dump an expr structure
 */
static void dump_expr(const struct expr *const expr, const unsigned depth)
{
    indent(depth);
    if (expr->not == TRUE)
	fputs(CD(COLOR_OPERATOR "!" COLOR_RESET " ", "! "), out_file);

    if (expr->type == EXPR_COND)
	dump_condition(expr->sub.cond);
    else {
	fputs(CD(COLOR_OPERATOR "(" COLOR_RESET "\n", "(\n"), out_file);

	dump_expr(expr->sub.expr.left, depth + 1);

	indent(depth);
	switch (expr->type) {
	case EXPR_AND:
	    fputs(CD(COLOR_OPERATOR "&&" COLOR_RESET "\n", "&&\n"), out_file);
	    break;

	case EXPR_OR:
	    fputs(CD(COLOR_OPERATOR "||" COLOR_RESET "\n", "||\n"), out_file);

	default:
	    break;
	}

	dump_expr(expr->sub.expr.right, depth + 1);

	indent(depth);
	fputs(CD(COLOR_OPERATOR ")" COLOR_RESET "\n", ")\n"), out_file);
    }
}

/*
 * Dump a condition structure
 */
static void dump_condition(const struct condition *const condition)
{
    const char *dir;
    static const char *const protos[] =
	    {"ip", "ipv4", "ipv6", "port", "tcp", "udp"};

    switch (condition->dir) {
    case DIR_BOTH:
	dir = "";
	break;

    case DIR_SRC:
	dir = CD(" " COLOR_DIR "source" COLOR_RESET, " source");
	break;

    case DIR_DST:
	dir = CD(" " COLOR_DIR "destination" COLOR_RESET, " destination");
	break;

    default:
	dir = "";
    }

    fprintf(out_file, CD(COLOR_PROTO "%s" COLOR_RESET "%s ", "%s%s "),
	    protos[condition->proto], dir);

    switch (condition->type) {
    case COND_ADDR:
	dump_addr(condition->cond.addr);
	break;

    case COND_PORT:
	dump_port(condition->cond.port);
	break;
    }

    putc('\n', out_file);
}

/*
 * Dump an addr structure
 */
static void dump_addr(const struct addr *addr)
{
    if (addr->next == NULL)
	dump_one_addr(addr);
    else {
	fputs(CD(COLOR_OPERATOR "{" COLOR_RESET " ", "{ "), out_file);
	dump_one_addr(addr);
	while ((addr = addr->next) != NULL) {
	    fputs(CD(COLOR_OPERATOR "," COLOR_RESET " ", ", "), out_file);
	    dump_one_addr(addr);
	}
	fputs(CD(" " COLOR_OPERATOR "}" COLOR_RESET, " }"), out_file);
    }
}

/*
 * Dump a one_addr structure
 */
static void dump_one_addr(const struct addr *const addr)
{
    fprintf(out_file, CD(COLOR_HOST "%s" COLOR_RESET, "%s"), addr->string);
}

/*
 * Dump a port structure
 */
static void dump_port(const struct port *port)
{
    if (port->next == NULL)
	dump_one_port(port);
    else {
	fputs(CD(COLOR_OPERATOR "{" COLOR_RESET " ", "{ "), out_file);
	dump_one_port(port);
	while ((port = port->next) != NULL) {
	    fputs(CD(COLOR_OPERATOR "," COLOR_RESET " ", ", "), out_file);
	    dump_one_port(port);
	}
	fputs(CD(" " COLOR_OPERATOR "}" COLOR_RESET, " }"), out_file);
    }
}

/*
 * Dump a one_port structure
 */
static void dump_one_port(const struct port *const port)
{
    fputs(CD(COLOR_PORT, ""), out_file);
    switch (port->type) {
    case PORT_NUMERIC:
	fprintf(out_file, "%u", (unsigned) port->port.range.from);
	if (port->port.range.to != port->port.range.from)
	    fprintf(out_file, "-%u", (unsigned) port->port.range.to);
	break;

    case PORT_NAME:
	fputs(port->port.name, out_file);
    }
    fputs(CD(COLOR_RESET, ""), out_file);
}

/* End of File */
