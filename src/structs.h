/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/structs.h
 *
 * Description: Structures Header File
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


/* Process only once */
#ifndef STRUCT_H
#define STRUCT_H

/* C++ protection */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* System headers */
#include <stdio.h> /* FILE * */


/*
 * Custom types: enumerations
 */

/* Boolean value */
enum bool { FALSE = 0, TRUE = 1 };

/* Final target */
enum final { FINAL_ACCEPT, FINAL_DROP, FINAL_REJECT };

/* Expression type */
enum expr_type { EXPR_COND, EXPR_AND, EXPR_OR };

/* Type of condition */
enum cond_type { COND_ADDR, COND_PORT };

/* Protocols */
enum proto { PROTO_IP = 0, PROTO_IPV4, PROTO_IPV6,
	     PROTO_PORT, PROTO_TCP, PROTO_UDP };

/* Packet direction */
enum direction { DIR_BOTH, DIR_SRC, DIR_DST };

/* A port range */
struct one_port { unsigned short from, to; };


/*
 * Custom types: structures
 */

/* Chain */
struct chain {
    struct chain *next;    /* Next chain (linked list) */
    char *name;            /* Chain name               */
    struct action *action; /* Associated action        */
};

/* Action */
struct action {
    enum { TARGET_FINAL, TARGET_USER, TARGET_TEST } type; /* Action type */
    union {
	enum final          final; /* Final target       */
	const struct chain *user;  /* User-defined chain */
	struct test        *test;  /* Test (conditions)  */
    } action;
};

/* Test */
struct test {
    struct expr *expr;                  /* Associated test expression */
    struct action *act_then, *act_else; /* Taken actions              */
};

/* Expression */
struct expr {
    enum bool not;       /* Wether to negate test ("!" operator) */
    enum expr_type type; /* Expression type                      */
    union {
	struct {
	    struct expr *left, *right; /* Left and right operands */
	} expr;
	struct condition *cond; /* Condition */
    } sub;
};

/* Condition */
struct condition {
    enum cond_type type; /* Condition type     */
    enum direction dir;  /* Packet direction   */
    enum proto proto;    /* Concerned protocol */
    union {
	struct addr *addr; /* Host address    */
	struct port *port; /* Port (TCP, UDP) */
    } cond;
};

/* Host address */
struct addr {
    struct addr *next; /* Next address (linked list) */
    char *string;      /* Corresponding string       */
};

/* Port number/range/name */
struct port {
    struct port *next;                     /* Next port range (linked list) */
    enum { PORT_NUMERIC, PORT_NAME } type; /* Port type                     */
    union {
	struct one_port range; /* Port range */
	char *name;            /* Port name  */
    } port;
};

/* Freeing functions */
extern void free_chain(struct chain *chain);
extern void free_action(struct action *action);
extern void free_test(struct test *test);
extern void free_expr(struct expr *expr);
extern void free_condition(struct condition *condition);
extern void free_addr(struct addr *addr);
extern void free_port(struct port *port);

/* Dumping functions */
extern void dump_config(const struct chain *chain, FILE *file,
			const char *prefix, enum bool comment,
			enum bool colors);

/* C++ protection */
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !STRUCT_H */

/* End of File */
