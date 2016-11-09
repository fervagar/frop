/*
 * Copyright (C) 2016 Fernando Vañó García
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *	Fernando Vanyo Garcia <fernando@fervagar.com>
 */

#define SETSIZE(list, s)			(list->size = s)
#define PAYLOAD(node) 				(node->payload)
#define SETVALUE(node, value)		(PAYLOAD(node) = ((void*) &(value)))
#define SETPOINTER(node, ptr)       (PAYLOAD(node) = ((void*) ptr))
#define GETVALUE(node, type)		(*((type*)(node->payload)))
#define GETPOINTER(node, type)		((type*)(&(node->payload)))

/**
 *  This is an old version of my linkedlist implementation. The updated version
 *  can be found at https://github.com/fervagar/C-collections
 */

struct Lnode {
	struct Lnode *prev;
	struct Lnode *next;
	void *payload;
};

struct list {
	struct Lnode *head;
	struct Lnode *tail;
	unsigned int size;
};

struct list *createList(int s);
struct Lnode *createLnode(struct list *list);
struct Lnode *deleteNode(struct list *list, struct Lnode *node);
struct Lnode *addBefore(struct list *list, struct Lnode *new_node, struct Lnode *existing_node);
struct Lnode *addHead(struct list *list, struct Lnode *node);
struct Lnode *addTail(struct list *list, struct Lnode *node);
void freeList(struct list *list);
