/* ---------------------------------------------------------------------------
 *
 * RuleWall: A Firewall Configuration Parser
 * Copyright (C) 2006 Benjamin Gaillard
 *
 * ---------------------------------------------------------------------------
 *
 *        File: src/memory.c
 *
 * Description: Memory Management Functions
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
#include <stddef.h> /* size_t                 */
#include <string.h> /* strlen(), strcpy()     */

/* Local headers */
#include "memory.h"


/*****************************************************************************
 *
 * Local Datatypes and Variables
 *
 */

/* Memory area structure (back and forward linked list) */
struct mem_area {
    struct mem_area *prev, *next; /* Previous and next element in list */
};

/* First element of the memory area linked list */
static struct mem_area *first = NULL;

/* Memory area count */
static unsigned count = 0;


/*****************************************************************************
 *
 * Flobal Functions
 *
 */

/*
 * Allocate memory and register the area in the linked list
 */
void *mem_alloc(const size_t size)
{
    /* Allocate memory */
    struct mem_area *const mem = malloc(sizeof(struct mem_area) + size);

    /* No more memory... */
    if (mem == NULL)
	return NULL;

    /* Initialize and link with the preceding one */
    if (first != NULL)
	first->prev = mem;
    mem->next = first;
    mem->prev = NULL;
    first = mem;

    /* Count it and return the actual reserved dataspace */
    count++;
    return mem + 1;
}

/*
 * Free a previously allocated dataspace
 */
void mem_free(void *const pointer)
{
    /* Pointer to actual memory area */
    struct mem_area *const mem = (struct mem_area *) pointer - 1;

    /* Unlink from the list */
    if (mem->prev != NULL)
	mem->prev->next = mem->next;
    else
	first = mem->next;
    if (mem->next != NULL)
	mem->next->prev = mem->prev;

    /* Free the area and retire it from the counter */
    free(mem);
    count--;
}

/*
 * Free all allocated memory
 */
void mem_free_all(void)
{
    struct mem_area *cur;

    /* Walk throuth the linked list and free all memory */
    for (cur = first; cur != NULL; cur = cur->next) {
	free(cur);
	count--;
    }

    /* Reinitialize list head */
    first = NULL;
}

/*
 * Get the count of the remaining allocated memory areas
 */
unsigned mem_get_count(void)
{
    return count;
}

/*
 * Duplicate a string by allocating space for it and copying it
 */
char *mem_strdup(const char *const string)
{
    /* Allocate space */
    char *mem = mem_alloc(strlen(string) + 1);

    /* Copy string */
    if (mem != NULL)
	strcpy(mem, string);
    return mem;
}

/* End of File */
