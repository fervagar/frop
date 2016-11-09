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

#include <stdlib.h>
#include "linkedlist.h"


struct list *createList(int s) {
	struct list *p;
	p = malloc(sizeof(struct list));
	p -> head = p -> tail = NULL;
	SETSIZE(p, s);
	return p;
};

struct Lnode *createLnode(struct list *list){
	struct Lnode *newnode;
	newnode = malloc( (sizeof(struct Lnode) - (sizeof(void*))) + list->size);
	newnode -> prev = newnode -> next = NULL;
	return newnode;
}

struct Lnode *deleteNode(struct list *list, struct Lnode *node){
	struct Lnode *aux;

	if(node != NULL){
		if(node->prev == NULL){ // HEAD node //
			aux = node;
			node = node->next;
			if(node != NULL){
				node->prev = NULL;
			}
			list->head = node;
		}
		else{
			aux = node->prev;
			aux->next = node->next;
			if(aux->next != NULL){
				(aux->next)->prev = aux;
			}
			else{
				list->tail = aux;
			}
			aux = node;
			node = node->next;
		}
		free(aux);
	}
	return node;
}

struct Lnode *addBefore(struct list *list, struct Lnode *new_node, struct Lnode *existing_node){
	struct Lnode *aux;

	if(new_node != NULL && existing_node != NULL){
		if(existing_node->prev == NULL){ // HEAD node //
			existing_node->prev = new_node;
			new_node->prev = NULL;
			new_node->next = existing_node;
			list->head = new_node;
		}
		else{
			aux = existing_node->prev;
			existing_node->prev = new_node;
			new_node->prev = aux;
			new_node->next = existing_node;
			aux->next = new_node;
		}
	}
	return new_node;
}

struct Lnode *addHead(struct list *list, struct Lnode *node){
	node -> prev = NULL;
	node -> next = list -> head;
	list -> head = node;
	if (list -> tail == NULL)
		list -> tail = node;
	else
		(node -> next) -> prev = node;

	return node;
}

struct Lnode *addTail(struct list *list, struct Lnode *node){
	node -> prev = list -> tail;
	node -> next = NULL;
	list -> tail = node;
	if (list -> head == NULL)
		list -> head = node;
	else
		(node -> prev) -> next = node;

	return node;
}

void freeList(struct list *list){
	struct Lnode *p;
	struct Lnode *next;

	if(list != NULL){
		for(p = list->head; p != NULL; p = next){
			next = p->next;
			free(p);
		}
	}
	free(list);
}
