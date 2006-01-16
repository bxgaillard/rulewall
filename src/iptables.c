/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/iptables.c
 *
 * Description: IPTables Rules Generation Functions
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
#include <stdlib.h> /* NULL, malloc(), free() */
#include <stdio.h> /* printf() */
#include <string.h> /* strdup(), strcmp() */

/* Local headers */
#include "structs.h"
#include "iptables.h"


/*****************************************************************************
 *
 * Prototypes and Local Variables
 *
 */

/* Default IPTables program name */
#define DEFAULT_IPT_EXE "iptables"

/* Auxiliary functions */
static void ipt_out_create(const char *table);
static char *ipt_new_table(const struct action *action);
static void ipt_out_jump(const char *table, const char *target);
static const char *make_port(const struct port *port);

/* Local functions */
static void ipt_chain(const struct chain *chain);
static void ipt_action(const char *table,
		       const struct action *action);
static void ipt_test(const char *table, const struct test *test);
static void ipt_expr(const char *table,
		     const char *tbl_then, const char *tbl_else,
		     const struct expr *expr);
static void ipt_cond(const char *table,
		     const char *tbl_then, const char *tbl_else,
		     const struct condition *cond);

/* Local variables */
static const char *const default_ipt_exe = "iptables";
static const char *ipt_exe;
static const char *cur_chain;
static FILE *out_file;


/*****************************************************************************
 *
 * Global Functions
 *
 */

void ipt_config(const struct chain *config, const char *const exe,
		FILE *const out)
{
    ipt_exe = exe == NULL ? default_ipt_exe : exe;
    out_file = out == NULL ? stdout : out;

    while (config != NULL) {
	putc('\n', out_file);
	ipt_chain(config);
	config = config->next;
    }

    ipt_exe = default_ipt_exe;
    out_file = stdout;
}


/*****************************************************************************
 *
 * Auxiliary Functions
 *
 */

/*
 * Output an IPTables table creation command
 */
static void ipt_out_create(const char *const table)
{
    fprintf(out_file, "%s -N %s\n", ipt_exe, table);
}

/*
 * Create an IPTables table for later use
 */
static char *ipt_new_table(const struct action *const action)
{
    static unsigned count = 0;
    unsigned digits = count, nb = 0;
    char *res;

    if (action != NULL)
	switch (action->type) {
	case TARGET_FINAL:
	    switch (action->action.final) {
	    case FINAL_ACCEPT:
		return strdup("ACCEPT");
	    case FINAL_DROP:
		return strdup("DROP");
	    case FINAL_REJECT:
		return strdup("REJECT");
	    }
	    break;

	case TARGET_USER:
	    return strdup(action->action.user->name);

	default:
	    break;
	}

    /* Count the number of digits */
    do {
	digits /= 10;
	nb++;
    } while (digits != 0);

    /* Allocate memory and build string */
    if ((res = malloc(nb + 5)) != NULL)
	sprintf(res, "__RW%u", count++);

    /* Output and return the result */
    ipt_out_create(res);
    return res;
}

/*
 * Output an IPTables jump rule
 */
static void ipt_out_jump(const char *const table, const char *const target)
{
    if ((table[0] == '_' && table[1] == '_') || strcmp(table, cur_chain) == 0)
	fprintf(out_file, "%s -A %s -j %s\n", ipt_exe, table, target);
}

/*
 * Make a string from the given port structure
 */
static const char *make_port(const struct port *const port)
{
    static char res[12];

    switch (port->type) {
    case PORT_NUMERIC:
	if (port->port.range.from == port->port.range.to)
	    sprintf(res, "%d", port->port.range.from);
	else
	    sprintf(res, "%d:%d", port->port.range.from, port->port.range.to);
	break;

    case PORT_NAME:
	return port->port.name;
    }

    return res;
}


/*****************************************************************************
 *
 * Local Functions
 *
 */

/*
 * Process a chain
 */
static void ipt_chain(const struct chain *const chain)
{
    cur_chain = chain->name;
    ipt_out_create(chain->name);
    ipt_action(chain->name, chain->action);
}

/*
 * Process an action
 */
static void ipt_action(const char *const table,
		       const struct action *const action)
{
    switch (action->type) {
    case TARGET_FINAL:
	switch (action->action.final) {
	case FINAL_ACCEPT:
	    ipt_out_jump(table, "ACCEPT");
	    break;

	case FINAL_DROP:
	    ipt_out_jump(table, "DROP");
	    break;

	case FINAL_REJECT:
	    ipt_out_jump(table, "REJECT");
	}
	break;

    case TARGET_USER:
	ipt_out_jump(table, action->action.user->name);
	break;

    case TARGET_TEST:
	ipt_test(table, action->action.test);
	break;
    }
}

/*
 * Process a test
 */
static void ipt_test(const char *const table, const struct test *const test)
{
    char *const tbl_then = ipt_new_table(test->act_then);
    char *const tbl_else = ipt_new_table(test->act_else);

    ipt_expr(table, tbl_then, tbl_else, test->expr);
    ipt_action(tbl_then, test->act_then);
    ipt_action(tbl_else, test->act_else);

    free(tbl_else);
}

/*
 * Process an expression
 */
static void ipt_expr(const char *const table,
		     const char *tbl_then, const char *tbl_else,
		     const struct expr *const expr)
{
    char *inter;

    if (expr->not) {
	const char *const tmp = tbl_then;
	tbl_then = tbl_else;
	tbl_else = tmp;
    }

    if (expr->type == EXPR_COND)
	ipt_cond(table, tbl_then, tbl_else, expr->sub.cond);
    else {
	inter = ipt_new_table(NULL);

	switch (expr->type) {
	case EXPR_AND:
	    ipt_expr(table, inter, tbl_else, expr->sub.expr.left);
	    break;

	case EXPR_OR:
	    ipt_expr(table, tbl_then, inter, expr->sub.expr.left);

	case EXPR_COND:
	    break;
	}
	ipt_expr(inter, tbl_then, tbl_else, expr->sub.expr.right);

	free(inter);
    }
}

/*
 * Process a condition
 */
static void ipt_cond(const char *const table,
		     const char *const tbl_then, const char *const tbl_else,
		     const struct condition *const cond)
{
    const struct addr *addr;
    const struct port *port;

    switch (cond->type) {
    case COND_ADDR:
	for (addr = cond->cond.addr; addr != NULL; addr = addr->next) {
	    if (cond->dir == DIR_BOTH || cond->dir == DIR_SRC)
		fprintf(out_file, "%s -A %s -s %s -j %s\n",
			ipt_exe, table, addr->string, tbl_then);
	    if (cond->dir == DIR_BOTH || cond->dir == DIR_DST)
		fprintf(out_file, "%s -A %s -d %s -j %s\n",
			ipt_exe, table, addr->string, tbl_then);
	}
	break;

    case COND_PORT:
	for (port = cond->cond.port; port != NULL; port = port->next) {
	    if (cond->proto == PROTO_PORT || cond->proto == PROTO_TCP) {
		if (cond->dir == DIR_BOTH || cond->dir == DIR_SRC)
		    fprintf(out_file, "%s -A %s -p tcp --sport %s -j %s\n",
			    ipt_exe, table, make_port(port), tbl_then);
		if (cond->dir == DIR_BOTH || cond->dir == DIR_DST)
		    fprintf(out_file, "%s -A %s -p tcp --dport %s -j %s\n",
			    ipt_exe, table, make_port(port), tbl_then);
	    }
	    if (cond->proto == PROTO_PORT || cond->proto == PROTO_UDP) {
		if (cond->dir == DIR_BOTH || cond->dir == DIR_SRC)
		    fprintf(out_file, "%s -A %s -p udp --sport %s -j %s\n",
			    ipt_exe, table, make_port(port), tbl_then);
		if (cond->dir == DIR_BOTH || cond->dir == DIR_DST)
		    fprintf(out_file, "%s -A %s -p udp --dport %s -j %s\n",
			    ipt_exe, table, make_port(port), tbl_then);
	    }
	}
    }

    ipt_out_jump(table, tbl_else);
}

/* End of File */
