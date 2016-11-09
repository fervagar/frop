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
#include "datatypes.h"
#include "linkedlist.h"

#define SIZE_BOOLEANS 4
#define WORD_PADDING  0x41414141

struct list *payload;
unsigned char state[4]; //Only for r0, r1, r2 & r7 in the 'instruction' generation
unsigned char written[4]; //Only for r0, r1, r2 & r7 in the 'data' generation
uint32_t store_values_r3[3], store_values_r4[3];
key_instructions_t key_instructions;
int store_count = 0;

// Vectors for inputs propagation (Only MOVs) //
unsigned char inputs_vector_state[14];
uint32_t inputs_vector_values[14];
// for optimize the auxiliar gadgets //
struct Lnode *inputs_vector_refs[14];

void process_inputs(struct Lnode *ptr);
void process_outputs(struct Lnode *ptr, struct Lnode *existing_node);
void print_python_syntax(struct list *payload);
void printMetadata(struct Lnode *ptr);

void clear_vector(unsigned char *vector, int size, unsigned char value){
  int i;

  for(i = 0; i < size; i++){
    vector[i] = value;
  }
}

void copy_vector(unsigned char *dst, unsigned char *src, int size){
  int i;

  for(i = 0; i < size; i++){
    dst[i] = src[i];
  }
}

// Boolean: Gadget 'gptr' writes into 'reg' //
unsigned char gadget_writes_r(struct Lnode *gadget, int reg){

  if(reg < 0 || reg > 15)
    return 0;
  else{
    return ((GETPOINTER(gadget, Gadget_t))->Outputs)[reg];
  }
}

unsigned char store_writes_r(int reg){
  struct Lnode *ptr = NULL;

  for(ptr = key_instructions.str; ptr->next != NULL; ptr = ptr->next); //'ret'
  return gadget_writes_r(ptr, reg);
}

struct Lnode *add_node_to_payload(uint32_t value, struct Lnode *gadget,
  char *string0, char *string1, char *string2, struct Lnode *existing_node){


  struct Lnode *new_node;
  payload_gadget_t *payload_node_ptr;

  new_node = createLnode(payload);
  payload_node_ptr = GETPOINTER(new_node, payload_gadget_t);

  /*
  if(GETPOINTER(gadget, Gadget_t)->instruction->instr_type == INS_RET){
    TODO
    < rename registers >
  }
  */

  payload_node_ptr->value = value;
  payload_node_ptr->gadget = gadget;
  payload_node_ptr->strings[0] = string0;
  payload_node_ptr->strings[1] = string1;
  payload_node_ptr->strings[2] = string2;

  if(existing_node){
    return addBefore(payload, new_node, existing_node);
  }
  else{
    addHead(payload, new_node);
    return 0;
  }
}

/* Returns the gadget which writes into 'reg' */
struct Lnode *get_gadget_pointer(int reg){
  struct Lnode *gadget = NULL;

  if(reg >= 3){
    reg = (reg < 13)? reg - 3 : 10; //r3 (idx: 0) .. r12 (idx: 9) && r14 (idx:10)
    gadget = key_instructions.Inputs[reg];
  }
  else{
    switch (reg) {
      case -1:
        // 'ret' of store //
        for(gadget = key_instructions.str;
          gadget->next != NULL; gadget = gadget->next);
        // now 'gadget' is the 'ret' node //
        break;
      case 0:
        gadget = key_instructions.write_r0;
        break;
      case 1:
        gadget = key_instructions.write_r1;
        break;
      case 2:
        gadget = key_instructions.write_r2;
        break;
    }
  }
  return gadget;
}

unsigned char check_my_outputs(int reg){
  struct Lnode *gadget = NULL;
  int i, *Outputs;

  gadget = get_gadget_pointer(reg);
  Outputs = GETPOINTER(gadget, Gadget_t)->Outputs;

  for(i = 0; i < 15; i++){
    if(i != reg && Outputs[i] && inputs_vector_state[i])
      return 1;
  }
  return 0;
}

void check_store_bools(unsigned char *booleans, int rs, int rd){
  /*
   * booleans[0] -> Store writes into rs
   * booleans[1] -> Store writes into rd
   * booleans[2] -> Auxiliar(rs) writes into rd
   * booleans[3] -> Auxiliar(rd) writes into rs
   */
  booleans[0] = gadget_writes_r(key_instructions.str, rs);
  booleans[1] = gadget_writes_r(key_instructions.str, rd);
  booleans[2] = gadget_writes_r(key_instructions.Inputs[rs - 3], rd);
  booleans[3] = gadget_writes_r(key_instructions.Inputs[rd - 3], rs);
}

/* Add auxiliar gadget to write in INPUT registers */
struct Lnode *write_auxiliar_gadget(int reg, struct Lnode *existing_node){
  Gadget_t *gadget_struct = NULL;
  struct Lnode *gadget = NULL;
  struct Lnode *aux = NULL;
  char *strings[3];
  uint32_t addr;
  int i, *Outputs;

  gadget = get_gadget_pointer(reg);
  gadget_struct = GETPOINTER(gadget, Gadget_t);
  addr = gadget_struct->instruction->addr;
  Outputs = gadget_struct->Outputs;

  for(i = 0; i < 14; i++){
    if(Outputs[i] && inputs_vector_state[i]){
      inputs_vector_state[i] = 0;
      //inputs_vector_refs[i] = 0;
    }
  }

  for(i = 0, aux = gadget; aux != NULL; aux = aux->next, i++){
      strings[i] = (GETPOINTER(aux, Gadget_t))->instruction->string;
    }
    for(; i < 3; i++)
      strings[i] = 0;


  process_outputs(gadget, existing_node);
  aux = add_node_to_payload(addr, gadget, strings[0], strings[1], strings[2], existing_node);
  //process_inputs(gadget);

  return aux;
}

void write_auxiliar_gadget_for_store(unsigned char *booleans, struct Lnode *existing_node){
  if( !(booleans[0] && booleans[1]) ){
    if( !(booleans[0] | booleans[1] | booleans[2] |booleans[3])  ){
      write_auxiliar_gadget(4, existing_node);
      write_auxiliar_gadget(3, existing_node);
    }
    else if( booleans[0] || (!booleans[1] && !booleans[2])  ){
      write_auxiliar_gadget(4, existing_node);
    }
    else{
      write_auxiliar_gadget(3, existing_node);
    }
  }
}

// Set the global INPUT vectors depending on the gadget //
void process_inputs(struct Lnode *ptr){
  Gadget_t *gadget_struct = NULL;
  effect_repr_t *effects_struct = NULL;
  struct Lnode *effects_node = NULL;
  int reg;

  if(ptr != NULL){
    gadget_struct = GETPOINTER(ptr, Gadget_t);
    // We only need the 'effects_struct' of 'ptr' //
    for(effects_node = (ptr->next == NULL)? NULL: gadget_struct->pointer.effects_node;
    effects_node != NULL; effects_node = effects_node->prev){
      effects_struct = GETPOINTER(effects_node, effect_repr_t);

      if(effects_struct->is_store){
        if(store_count <= 2){
          inputs_vector_values[effects_struct->rs] = store_values_r3[store_count];
          inputs_vector_values[effects_struct->rd] = store_values_r4[store_count];
        }
        inputs_vector_state[effects_struct->rs] = 1;
        inputs_vector_refs[effects_struct->rs] = 0;
        inputs_vector_state[effects_struct->rd] = 1;
        inputs_vector_refs[effects_struct->rd] = 0;
        store_count++;
      }
      else{
        //At the moment, only 'MOV' implemented
        reg = (effects_struct->rd == 7)? 3 : effects_struct->rd; //destination r0, r1, r2 or r7

        if(effects_struct->operation == OP_MOV && (reg <= 3)){
          if(!effects_struct->use_inmediate && (effects_struct->rd != effects_struct->rs)){

            if(inputs_vector_state[effects_struct->rd]){
              // dest is already a required input //
              inputs_vector_state[effects_struct->rd] = 0;
              inputs_vector_state[effects_struct->rs] = 1;
              inputs_vector_refs[effects_struct->rs] = 0;
              inputs_vector_values[effects_struct->rs] = inputs_vector_values[effects_struct->rd];
            }
            else{
          //    printf("[DEBUG] reg: %d; rs: %d; state[reg] = %d\n", reg, effects_struct->rs, state[reg]);
          //    printf("inputs_vector_values[rs] = 0x%x; inputs_vector_values[rd] = 0x%x\n", inputs_vector_values[effects_struct->rs], inputs_vector_values[effects_struct->rd]);
              switch (reg) {
                case 0:
                  inputs_vector_values[effects_struct->rs] = (!written[reg])? key_instructions.r_w_addr : WORD_PADDING;
                  break;
                case 1:
                  inputs_vector_values[effects_struct->rs] = (!written[reg])? key_instructions.r_w_addr + 8 : WORD_PADDING;
                  break;
                case 2:
                  inputs_vector_values[effects_struct->rs] = (!written[reg])? 0 : WORD_PADDING;
                  break;
                case 3:
                  inputs_vector_values[effects_struct->rs] = (!written[reg])? 11 : WORD_PADDING;
                  break;
              }
              inputs_vector_state[effects_struct->rs] = 1;
              inputs_vector_refs[effects_struct->rs] = 0;
              if(reg <= 3) written[reg] = 1;
            }
          }
        }
      }
    }
  }
}

// Fix dependences between pending INPUTS and gadget OUTPUTS //
void process_outputs(struct Lnode *ptr, struct Lnode *existing_node){
  Gadget_t *gadget_struct = NULL;
  effect_repr_t *effects_struct = NULL;
  struct Lnode *effects_node = NULL;
  unsigned char booleans[SIZE_BOOLEANS];
  int i, *Outputs;

  if(ptr != NULL){
    // reuse 'effects_node' var
    for(effects_node = ptr; effects_node->next != NULL; effects_node = effects_node->next);
    // now 'effects_node' is the 'ret' node //
    Outputs = (GETPOINTER(effects_node, Gadget_t))->Outputs;
    for(i = 14; i >= 0; i--){
      if(Outputs[i] && inputs_vector_state[i]){
        inputs_vector_state[i] = 0;
      }
    }
    if(Outputs[7])
      state[3] = 1;

    gadget_struct = GETPOINTER(ptr, Gadget_t);

    //We only need the 'effects_struct' of 'ptr'
    for(effects_node = (ptr->next == NULL)? NULL: gadget_struct->pointer.effects_node;
    effects_node != NULL; effects_node = effects_node->prev){
      effects_struct = GETPOINTER(effects_node, effect_repr_t);

      if(effects_struct->is_store){
        check_store_bools(booleans, 3, 4);
        write_auxiliar_gadget_for_store(booleans, existing_node);
      }
      else if(effects_struct->operation == OP_MOV){
        //if(inputs_vector_state[effects_struct->rs])

        if(inputs_vector_state[effects_struct->rd]){ // 'rd' is a required input

          if(effects_struct->use_inmediate){
            if(inputs_vector_refs[effects_struct->rd]){
              write_auxiliar_gadget(effects_struct->rd, inputs_vector_refs[effects_struct->rd]);
            }
            else{
              write_auxiliar_gadget(effects_struct->rd, existing_node);
            }
          }
          else{
            inputs_vector_values[effects_struct->rs] = inputs_vector_values[effects_struct->rd];
            inputs_vector_state[effects_struct->rd] = 0;
            inputs_vector_state[effects_struct->rs] = 1;
            inputs_vector_refs[effects_struct->rs] = existing_node;
          }
        }
      }
    }
  }
}

void write_gadget(struct Lnode *ptr){
  struct Lnode *backup_ptr;
  char *strings[3];
  uint32_t addr;
  int i;

  addr = GETPOINTER(ptr, Gadget_t)->instruction->addr;
  backup_ptr = ptr;

  for(i = 0; ptr != NULL; ptr = ptr->next, i++){
    strings[i] = (GETPOINTER(ptr, Gadget_t))->instruction->string;
  }
  for(; i < 3; i++)
    strings[i] = 0;

  add_node_to_payload(addr, backup_ptr, strings[0], strings[1], strings[2], 0);
}

void set_register(int reg){
  struct Lnode *ptr = NULL;

  if(reg == 7)
    reg = 3;

  switch (reg) {
    case -1: //Store instuctions
      ptr = key_instructions.str;
      break;
    case 0:
      ptr = key_instructions.write_r0;
      break;
    case 1:
      ptr = key_instructions.write_r1;
      break;
    case 2:
      ptr = key_instructions.write_r2;
      break;
    case 3:
      ptr = key_instructions.Inputs[7-3];
      break;
  }

  if(ptr != NULL){
    process_outputs(ptr, payload->head);
    write_gadget(ptr);
    process_inputs(ptr);
    if(reg >= 0){
      state[reg] = 1;
    }
  }
}

void first_stage(int r2_missing){
  inputs_vector_state[7] = 1; //r7 pending
  inputs_vector_values[7] = 11;
  inputs_vector_refs[7] = 0;

  // Beginning of payload building //

  add_node_to_payload(key_instructions.svc->addr, 0, key_instructions.svc->string, 0, 0, 0);

  // If writer r0 doesn't write into r1 ... //
  if(!gadget_writes_r(key_instructions.write_r0, 1)){
    set_register(1);
  }

  if(!state[0]){
    set_register(0);
  }

  if(!state[2] && !r2_missing){
    set_register(2);
  }

  if(!state[3] && !store_writes_r(7)){
    set_register(7);
  }
}

void write_stores(){
  unsigned char store_writes_r3, store_writes_r4;
  struct Lnode *store_pop = NULL;
  int i, j, *Outputs[3], sum[3];

  for(i = 0; i < 3; i++){
    process_inputs(key_instructions.str);
    write_gadget(key_instructions.str);
    process_outputs(key_instructions.str, payload->head);
  }

  store_writes_r3 = store_writes_r(3);
  store_writes_r4 = store_writes_r(4);


  if(store_writes_r3 | store_writes_r4){
    if(store_writes_r3 && store_writes_r4){
      for(store_pop = key_instructions.str;
        store_pop->next != NULL; store_pop = store_pop->next);
      Outputs[0] = (GETPOINTER(store_pop, Gadget_t))->Outputs;
      Outputs[1] = (GETPOINTER(key_instructions.Inputs[3-3], Gadget_t))->Outputs;
      Outputs[2] = (GETPOINTER(key_instructions.Inputs[4-3], Gadget_t))->Outputs;

      for(j = 0; j < 3; j++){
        sum[j] = 0;
        for(i = 0; i < 14; i++){
          if(Outputs[j][i]){
            sum[j]++;
          }
        }
      }
      if( (sum[0] - 1) <= sum[1] + sum[2]){
        write_auxiliar_gadget(-1, payload->head); //'pop' of the store
      }
      else{
        write_auxiliar_gadget(4, payload->head);
        write_auxiliar_gadget(3, payload->head);
      }
    }
    else if(store_writes_r3){
      write_auxiliar_gadget(3, payload->head);
    }
    else{
      write_auxiliar_gadget(4, payload->head);
    }
  }
}

void resolve_dependences(){
  struct Lnode *payload_node = NULL;
  payload_gadget_t *payload_node_struct = NULL;
  /* Local state of pending inputs (previous iteration) */
  unsigned char inputs_vector_state_LOCAL[14];
  unsigned char looping = 1;
  int i;

  while(looping){
    copy_vector(inputs_vector_state_LOCAL, inputs_vector_state, 14);
    clear_vector(inputs_vector_state, 14, 0);
    inputs_vector_state[7] = 1;
    inputs_vector_values[7] = 11;
    inputs_vector_refs[7] = 0;

    for(payload_node = payload->tail; payload_node != NULL; payload_node = payload_node->prev){
      payload_node_struct = GETPOINTER(payload_node, payload_gadget_t);
      process_outputs(payload_node_struct->gadget, payload_node);
      process_inputs(payload_node_struct->gadget);
      for(i = 0; i < 14; i++){
        if(inputs_vector_state[i] && inputs_vector_state_LOCAL[i]){
          // Input not provided //
          if(payload_node != payload->head || !store_writes_r(i)){
            // Fix it
            if(check_my_outputs(i)){
              // Auxiliar gadget (which writes into i) writes also into another pending input //
              inputs_vector_refs[i] = payload_node;
            }
            else{
              payload_node = write_auxiliar_gadget(i, payload_node);
            }
          }
        }
      }
    }

    looping = 0;
    for(i = 0; i < 14; i++){
      if(inputs_vector_state[i] && !store_writes_r(i)){
        write_auxiliar_gadget(i, payload_node);
        looping = 1;
      }
    }
  }
}

void debug_print_key_instructions(){
  int i;

  printf("--------------------------------------------\n");
  printMetadata(key_instructions.write_r0);
  printMetadata(key_instructions.write_r1);
  printMetadata(key_instructions.write_r2);
  printMetadata(key_instructions.str);
  printf("SVC Address: 0x%08x\n", key_instructions.svc->addr);
  printf("R/W Segment Address: 0x%08x\n", key_instructions.r_w_addr);

  printf("****\nGLOBAL Inputs: \n");
  for(i = 0; i < 10; i++)
    if(key_instructions.Inputs[i]){
      printf("---------- [r%d]: ----------\n", i+3);
      printMetadata(key_instructions.Inputs[i]);
    }
  if(key_instructions.Inputs[10]){
    printf("---------- [r%d]: ----------\n", 14);
    printMetadata(key_instructions.Inputs[10]);
  }
}

void debug_print_payload(){
  payload_gadget_t *payload_node_ptr;
  struct Lnode *aux_ptr;

  for(aux_ptr = payload->head; aux_ptr != NULL; aux_ptr = aux_ptr->next){
    payload_node_ptr = GETPOINTER(aux_ptr, payload_gadget_t);
    printf("0x%08x\t", payload_node_ptr->value);
    if(payload_node_ptr->strings[0])
      printf("%s; ", payload_node_ptr->strings[0]);
    if(payload_node_ptr->strings[1])
      printf("%s; ", payload_node_ptr->strings[1]);
    if(payload_node_ptr->strings[2])
      printf("%s; ", payload_node_ptr->strings[2]);
    //printf(" [0x%x]; ", payload_node_ptr);
    printf("\n");
  }
}

struct Lnode *insert_word(uint32_t value, struct Lnode *node){
  return add_node_to_payload(value, 0, 0, 0, 0, node);
}

uint32_t getValue(int reg){
  if(inputs_vector_state[reg])
    return inputs_vector_values[reg];
  else return WORD_PADDING;
}

void write_data(){
  struct Lnode *actual_node = NULL;
  struct Lnode *next_node = NULL;
  struct Lnode *ptr = NULL;
  int i, *Outputs;
  uint32_t value;

  clear_vector(inputs_vector_state, 14, 0);
  clear_vector(written, 4, 0);

  inputs_vector_state[7] = 1;
  inputs_vector_values[7] = 11;
  store_count = 0;
  store_values_r3[0] = 0;
  store_values_r3[1] = SH_HEX;
  store_values_r3[2] = BIN_HEX;
  store_values_r4[0] = key_instructions.r_w_addr + 8;
  store_values_r4[1] = key_instructions.r_w_addr + 4;
  store_values_r4[2] = key_instructions.r_w_addr;

  for(actual_node = payload->tail; actual_node != NULL; actual_node = actual_node->prev){
    next_node = actual_node->prev;
    if(next_node == NULL) break;

    for(ptr = (GETPOINTER(next_node, payload_gadget_t))->gadget;
          ptr != NULL && ptr->next != NULL; ptr = ptr->next); //'ret'
    Outputs = (GETPOINTER(ptr, Gadget_t))->Outputs;

    if(Outputs[0] && !written[0]){
      written[0] = 1;
      inputs_vector_state[0] = 1;
      inputs_vector_values[0] = key_instructions.r_w_addr;
    }
    if(Outputs[1] && !written[1]){
      written[1] = 1;
      inputs_vector_state[1] = 1;
      inputs_vector_values[1] = key_instructions.r_w_addr + 8;
    }
    if(Outputs[2] && !written[2]){
      written[2] = 1;
      inputs_vector_state[2] = 1;
      inputs_vector_values[2] = 0;
    }

    for(i = 14; i >= 0; i--){
      if(Outputs[i]){
        value = getValue(i);
        actual_node = insert_word(value, actual_node);
      }
    }

    if(Outputs[7] && !written[3]){
      written[3] = 1;
      inputs_vector_values[7] = WORD_PADDING;
    }

    process_inputs(GETPOINTER(next_node, payload_gadget_t)->gadget);
  }
}
void build_payload_bin_sh(int r2_missing){
  int i;

  payload = createList(sizeof(payload_gadget_t));

  for(i = 0; i < 4; i++){
    state[i] = 0;
  }
  for(i = 0; i < 14; i++){
    inputs_vector_state[i] = 0;
  }

  first_stage(r2_missing);

  resolve_dependences();

  write_stores();

  write_data();

  print_python_syntax(payload);

  freeList(payload);
}
