/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/iptables.h
 *
 * Description: IPTables Rules Generation Functions Header
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
#ifndef IPTABLES_H
#define IPTABLES_H

/* C++ protection */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* System headers */
#include <stdio.h> /* FILE * */

/* IPTables-related functions */
void ipt_config(const struct chain *config, const char *exe, FILE *out);

/* C++ protection */
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !IPTABLES_H */

/* End of File */
