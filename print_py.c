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

#include <stdio.h>
#include <string.h>
#include "datatypes.h"
#include "linkedlist.h"

#define VAR_NAME  "payload"
#define OFF_NAME  "offset"
#define BUFFER_SIZE 200

char *rename_pop_registers(char *dest, const char *src, int dest_size);

// Rename the instructions before print //
// sl [r10]; fp [r11]; ip [r12]; sp [r13]; lr [r14]; pc [r15]; //
void print_return(char *ret_string){
  char buffer[BUFFER_SIZE];

  rename_pop_registers(buffer, ret_string, BUFFER_SIZE);
  printf(" %s;", buffer);
}

void print_python_syntax(struct list *payload){
  payload_gadget_t *payload_node_ptr;
  struct Lnode *aux_ptr;
  char *str_ptr;
  int i;

  printf(VAR_NAME " = 'A' * " OFF_NAME ";\n");

  for(aux_ptr = payload->head; aux_ptr != NULL; aux_ptr = aux_ptr->next){
    payload_node_ptr = GETPOINTER(aux_ptr, payload_gadget_t);

    printf(VAR_NAME " += pack('<L', 0x%08x);", payload_node_ptr->value);

    if(payload_node_ptr->strings[0]){
      printf(" ##");

      for(i = 0; i <= 2; i++){
        str_ptr = payload_node_ptr->strings[i];
        if(str_ptr){
          if(strstr(str_ptr, "pop")){
            print_return(str_ptr);
          }
          else{
            printf(" %s;", str_ptr);
          }
        }
      }
    }
    // Always //
    printf("\n");
  }


}
