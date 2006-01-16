/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/memory.h
 *
 * Description: Memory Management Functions Header
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
#ifndef MEMORY_H
#define MEMORY_H

/* C++ protection */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* System headers */
#include <stddef.h> /* size_t */

/* Memory management functions */
void *mem_alloc(size_t size);
void mem_free(void *pointer);
void mem_free_all(void);
unsigned mem_get_count(void);
char *mem_strdup(const char *string);

/* C++ protection */
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !MEMORY_H */

/* End of File */
