
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
 *	Fernando Vanyo Garcia <fervagar@tuta.io>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "datatypes.h"
#include "linkedlist.h"
#include "disass.h"

// max length of gadgets in repository //
#define MAX_REPO_GADGETS  2

extern struct list *gadgets;
extern Elf32_Phdr *readwriteSegm;
key_instructions_t key_instructions; //Final gadgets

struct r_node_data{
  int score;
  struct Lnode *node;
};

/*
* repository[0] => writers_r0;
* repository[1] => writers_r1;
* repository[2] => writers_r2;
* repository[3] => store;
*/
struct list *repository[4];
struct list *auxiliars_repo[AUXILIAR_REGS];

// [disass.c] //
extern unsigned char check_gadget_len(struct Lnode *ptr, int n);

// [sm.c] //
int build_payload_bin_sh(int r2_missing);

/////
int check_inputs(int r2_missing);

uint32_t get_opcode_data_instr(unsigned char cond, unsigned char inm,
                                        unsigned char d_opcode, unsigned char rn,
                                        unsigned char rd, unsigned int operand2){
//        // Cond //     // Inmediate //        // Data Opcode //            // Rn //            // Rd //           // Operand2 //
  return (cond << 28) | ((inm & 1) << 25) | ((d_opcode & 0xf) << 21) | ((rn & 0xf) << 16) | ((rd & 0xf) << 12) | (operand2 & 0xfff);
}
uint32_t get_opcode_mem_single_instr(unsigned char cond,
                                     unsigned char inm_reg,
                                     unsigned char pre_post,
                                     unsigned char up_down,
                                     unsigned char byte_word,
                                     unsigned char writeback,
                                     unsigned char load_store,
                                     unsigned char rn,
                                     unsigned char rd,
                                     unsigned int offset){

  return (cond << 28) | (1 << 26) | ((inm_reg & 1) << 25)
            | ((pre_post & 1) << 24) | ((up_down & 1) << 23)
            | ((byte_word & 1) << 22) | ((writeback & 1) << 21)
            | ((load_store & 1) << 20) | ((rn & 0xf) << 16)
            | ((rd & 0xf) << 12) | (offset & 0xfff);
}

inline void fill_vector(int *vector, int size, int value){
  int i;
  for(i = 0; i < size; i++)
    vector[i] = value;
}

inline void fill_zero(effect_repr_t *effects_ptr){
  effects_ptr->two_operands = 0;
  effects_ptr->use_inmediate = 0;
  effects_ptr->is_store = 0;
  effects_ptr->neg_offset = 0;
  effects_ptr->override = OVERRIDE_NONE;
  effects_ptr->rd = 0;
  effects_ptr->rs = 0;
  effects_ptr->rn = 0;
  effects_ptr->operation = 0;
  effects_ptr->value = 0;
  effects_ptr->extra_value = 0;
  effects_ptr->extra_operation = 0;
}

//  if 'existing_node' != NULL, we add the new node before //
struct Lnode *addNode_to_repo(int score, struct Lnode *node, struct list *register_l, struct Lnode *existing_node){
  struct Lnode *new_node;
  struct r_node_data *data;

  if(node != NULL && register_l != NULL){
    new_node = createLnode(register_l);
    data = GETPOINTER(new_node, struct r_node_data);
    data->score = score;
    data->node = node;

    if(existing_node){
      return addBefore(register_l, new_node, existing_node);
    }
    else{
      return addTail(register_l, new_node);
    }
  }
  else
    return NULL;
}

// Delete a node if 'rd' is in the 'pop{...}' //
void clearEffects(int pop_regs[15], struct list *list){
  effect_repr_t *effects_ptr = NULL;
  struct Lnode *ptr = NULL;

  ptr = list->head;
  while(ptr != NULL){
    effects_ptr = GETPOINTER(ptr, effect_repr_t);

    if(!(effects_ptr->is_store) && (pop_regs[effects_ptr->rd] == 1)){
      ptr = deleteNode(list, ptr);
    }
    else
      ptr = ptr->next;
  }
}

// DEBUGGING PURPOSE //
void printMetadata(struct Lnode *ptr){
  int i;
  int *Inputs;
  int *Outputs;
  effect_repr_t *effects_ptr = NULL;
  Gadget_t *gadget_struct = NULL;
  instr_obj_32 *instruction_ptr = NULL;
  struct Lnode *node_ptr = ptr;

  if(node_ptr != NULL){
    gadget_struct = GETPOINTER(node_ptr, Gadget_t);
    Inputs = gadget_struct->Inputs;
    Outputs = gadget_struct->Outputs;


    for(; node_ptr != NULL; node_ptr = node_ptr->next){
      instruction_ptr = (GETPOINTER(node_ptr, Gadget_t))->instruction;
      printf(" %08x:\t%08x\t%s\t\n", instruction_ptr->addr, instruction_ptr->opcode, instruction_ptr->string);
    }

    printf("-> Inputs:\t");
    for(i = 0; i < 15; i++) if(Inputs[i] == 1) printf("r%d ", i);
    printf("\n");

    printf("-> Outputs:\t");
    for(i = 0; i < 15; i++) if(Outputs[i] == 1) printf("r%d ", i); //r15 is surely in
    printf("\n");

    if(ptr->next == NULL){ //'ret' node
      node_ptr = NULL;
    }
    else{
      node_ptr = gadget_struct->pointer.effects_node;
      printf("-> Effects:\n");
    }
  }

  for(; node_ptr != NULL; node_ptr = node_ptr->prev){
    effects_ptr = GETPOINTER(node_ptr, effect_repr_t);
    if(effects_ptr->is_store){
      // STR INSTRUCTIONS //
      if(effects_ptr->use_inmediate){ //OVERRIDED
        if(effects_ptr->extra_value){ //Offset
          if(effects_ptr->neg_offset)
            printf("[r%d - #%d] <- #%d\n",effects_ptr->rd, (effects_ptr->extra_value*-1), effects_ptr->rs);
          else
            printf("[r%d + #%d] <- #%d\n",effects_ptr->rd, effects_ptr->extra_value, effects_ptr->rs);
        }
        else{
          printf("[r%d] <- #%d\n",effects_ptr->rd, effects_ptr->rs);
        }
      }
      else{
        if(effects_ptr->extra_value){
          if(effects_ptr->neg_offset)
            printf("[r%d - #%d] <- r%d\n",effects_ptr->rd, (effects_ptr->extra_value*-1), effects_ptr->rs);
          else
            printf("[r%d + #%d] <- r%d\n",effects_ptr->rd, effects_ptr->extra_value, effects_ptr->rs);
        }
        else{
          printf("[r%d] <- r%d\n",effects_ptr->rd, effects_ptr->rs);
        }
      }
    }
    else{
      // DATA INSTRUCTIONS //
      if(effects_ptr->override == OVERRIDE_NONE){
        if(effects_ptr->use_inmediate){
          if(effects_ptr->two_operands){
            printf("r%d <- r%d OP #%d\top: %d\n",effects_ptr->rd, effects_ptr->rs, effects_ptr->value, effects_ptr->operation);
          }
          else{
            printf("r%d <- #%d\n",effects_ptr->rd, effects_ptr->value);
          }
        }
        else{
          if(effects_ptr->two_operands){
            printf("r%d <- r%d OP r%d\top: %d\n",effects_ptr->rd, effects_ptr->rs, effects_ptr->rn, effects_ptr->operation);
          }
          else{
            printf("r%d <- r%d\top: %d\n",effects_ptr->rd, effects_ptr->rs, effects_ptr->operation);
          }
        }
      }
      else{ //OVERRIDE RESULTS

        if(effects_ptr->override == OVERRIDE_SIMP){
          if(effects_ptr->use_inmediate){
            printf("r%d <- #%d OP r%d\top: %d\n",effects_ptr->rd, effects_ptr->value, effects_ptr->rn, effects_ptr->operation);
          }
          else{
            printf("r%d <- r%d OP r%d\top: %d\n",effects_ptr->rd, effects_ptr->rs, effects_ptr->rn, effects_ptr->operation);
          }
        }
        else if(effects_ptr->override == OVERRIDE_INM_INM){
          printf("r%d <- (r%d OP_1 #%d) OP_2 #%d\top1: %d; op2: %d\n",
            effects_ptr->rd, effects_ptr->rs, effects_ptr->extra_value, effects_ptr->value, effects_ptr->extra_operation, effects_ptr->operation);
        }
        else if(effects_ptr->override == OVERRIDE_INM_REG){
          printf("r%d <- (r%d OP_1 r%d) OP_2 #%d\top1: %d; op2: %d\n",
            effects_ptr->rd, effects_ptr->rs, effects_ptr->rn, effects_ptr->value, effects_ptr->extra_operation, effects_ptr->operation);
        }
        else if(effects_ptr->override ==  OVERRIDE_REG_INM_A){
          printf("r%d <- r%d OP_1 (r%d OP_2 #%d)\top1: %d; op2: %d\n",
            effects_ptr->rd, effects_ptr->rs, effects_ptr->rn, effects_ptr->extra_value, effects_ptr->operation, effects_ptr->extra_operation);
        }
        else if(effects_ptr->override == OVERRIDE_REG_INM_B){
          printf("r%d <- (r%d OP_1 #%d) OP_2 r%d\top1: %d; op2: %d\n",
            effects_ptr->rd, effects_ptr->rs, effects_ptr->extra_value, effects_ptr->rn, effects_ptr->extra_operation, effects_ptr->operation);
        }
        else if(effects_ptr->override == OVERRIDE_REG_REG_A){
          printf("r%d <- r%d OP_1 (r%d OP_2 r%d)\top1: %d; op2: %d\n",
            effects_ptr->rd, effects_ptr->rs, effects_ptr->rn, effects_ptr->extra_value, effects_ptr->extra_operation, effects_ptr->operation);
        }
        else if(effects_ptr->override == OVERRIDE_REG_REG_B){
          printf("r%d <- (r%d OP_1 r%d) OP_2 r%d\top1: %d; op2: %d\n",
            effects_ptr->rd, effects_ptr->rs, effects_ptr->rn, effects_ptr->extra_value, effects_ptr->extra_operation, effects_ptr->operation);
        }
      }

    }
    if(check_gadget_len(node_ptr, MAX_GADGET_LENGTH)) break; /// 3 at the moment.......
  }
}

// Builds the Effects list //
// /!\ At the moment only works for gadgets of length <= 3 /!\ (MAX_GADGET_LENGTH) //
void getMetadata(struct list *gadget){
  int i, j, reg_sd;
  uint8_t modify_prev_boolean; // In case the destination is a source of a subsequent instruction //
  // Linked list of Effects of a gadget//
  static struct list *glob_effects_list = NULL;
  instr_obj_32 *instruction_ptr = NULL;
  struct Lnode *node_ptr = NULL;
  struct Lnode *new_node = NULL;
  struct Lnode *ptr_aux = NULL;
  effect_repr_t *effects_ptr = NULL;
  effect_repr_t *prev_effects_ptr = NULL;
  Gadget_t *gadget_struct = NULL;

  int Inputs[15];
  int Outputs[15];
  int pop_regs[15];

  fill_vector(Inputs, 15, 0);
  fill_vector(Outputs, 15, 0);
  fill_vector(pop_regs, 15, 0);

  glob_effects_list = createList(sizeof(effect_repr_t)); //Freed in freeGadgets()
  for(node_ptr = gadget->tail; node_ptr != NULL; node_ptr = node_ptr->prev){
    gadget_struct = GETPOINTER(node_ptr, Gadget_t);
    instruction_ptr = gadget_struct->instruction;

    //printf(" %08x:\t%08x\t%s\t\n", instruction_ptr->addr, instruction_ptr->opcode, instruction_ptr->string);
    reg_sd = (instruction_ptr->opcode >> 12 & 0xf);
    modify_prev_boolean = Inputs[reg_sd];

    if(instruction_ptr->instr_type == INS_RET){
      j =  (instruction_ptr->regs >> 16);
      for(i = 0; i < 16; i++){
        if( (j >> i) & 1 ){
          Outputs[i] = 1;
          pop_regs[i] = 1;
        }
      }
      gadget_struct->pointer.effects_list = glob_effects_list; // Only the 'ret' nodes
    }
    else{
      new_node = createLnode(glob_effects_list);
      effects_ptr = GETPOINTER(new_node, effect_repr_t);
      fill_zero(effects_ptr);
      gadget_struct->pointer.effects_node = new_node; // The other nodes

      if(instruction_ptr->instr_type == INS_DATA){
        effects_ptr->is_store = 0;
        i = 16;
        if(instruction_ptr->operation == OP_EOR){
          if( !(instruction_ptr->use_inmediate)){
            for(i = 0; i < 16; i++){
              j = (instruction_ptr->regs >> i) & 1;
              if( j && i == reg_sd ){
                if(!Outputs[i]){ //POP will not override
                  // r_i <- #0
                  effects_ptr->two_operands = 0;
                  effects_ptr->use_inmediate = 1;
                  effects_ptr->rd = reg_sd;
                  effects_ptr->value = 0; //#0 value
                  Outputs[reg_sd] = 1;
                  addTail(glob_effects_list, new_node);
                  break;
                }
              }
            }
          }
        }
        if(i == 16){ // it's not 'eor rX, rX' //
          if(!Outputs[reg_sd] || Inputs[reg_sd]){
            effects_ptr->two_operands = (instruction_ptr->operation <= OP_ORR)? 1 : 0;
            effects_ptr->use_inmediate = instruction_ptr->use_inmediate;
            effects_ptr->rd = reg_sd;
            effects_ptr->operation = instruction_ptr->operation;
            effects_ptr->value = instruction_ptr->inmediate;

            if(effects_ptr->two_operands)
              effects_ptr->rs = ((instruction_ptr->opcode)>>16) & 0xf;
            else
              effects_ptr->rn = ((instruction_ptr->opcode)>>16) & 0xf;

            for(i = 0, j = instruction_ptr->regs; i < 16; i++){
              if((j >> i) & 1){
                Inputs[i] = 1;
                if(effects_ptr->two_operands && effects_ptr->rs != i){
                  effects_ptr->rn = i;
                }
                else{
                  effects_ptr->rs = i;
                  if(effects_ptr->use_inmediate)
                    break;
                }
              }
            }
            //printf("[ %s ]: rd: %d; rs: %d; op: %d\n", instruction_ptr->string, effects_ptr->rd, effects_ptr->rs, effects_ptr->operation);
            addTail(glob_effects_list, new_node);

            if(!Outputs[reg_sd]){ //Is the 'last' instruction which writes in 'reg_sd'
              Outputs[reg_sd] = 1;
            }
            if (modify_prev_boolean){ //reg_sd is an Output BUT it's needed by the next instruction
              Inputs[reg_sd] = 0;
            }

          }
        }
      }
      else if(instruction_ptr->instr_type == INS_STR){ //str rs, [rd]
        j = instruction_ptr->regs;
        for(i = 16; i < 32; i++){
          if((j >> i) & 1){
            effects_ptr->is_store = 1;
            effects_ptr->neg_offset = !((instruction_ptr->opcode>>23) & 0x1);
            effects_ptr->rs = reg_sd;
            effects_ptr->rd = i-16; //
            //effects_ptr->operation = instruction_ptr->operation;
            effects_ptr->value = 0; //Clear
            effects_ptr->extra_value = instruction_ptr->inmediate; //Offset
            Inputs[reg_sd] = 1;
            Inputs[i-16] = 1;

            if(instruction_ptr->opcode>>21 & 1){ //Store with writeback
              ptr_aux = createLnode(glob_effects_list);
              prev_effects_ptr = GETPOINTER(ptr_aux, effect_repr_t); //Reuse the 'prev_effects_ptr' pointer

              prev_effects_ptr->two_operands = 1;
              prev_effects_ptr->use_inmediate = 1;
              prev_effects_ptr->is_store = 0;
              prev_effects_ptr->override = OVERRIDE_NONE;
              prev_effects_ptr->rd = effects_ptr->rd; //rd of the store
              prev_effects_ptr->rs = prev_effects_ptr->rd;
              prev_effects_ptr->operation = OP_ADD;
              prev_effects_ptr->value = effects_ptr->extra_value; //offset
              Outputs[effects_ptr->rd] = 1;
              addTail(glob_effects_list, ptr_aux);
            }

            addTail(glob_effects_list, new_node);
            break;
          }
        }
      }
    }

    /*


    //TODO
    //  BUG TO FIX: if we have a "mov r3, #0; str  r3, [r4]; ret" then we clear and //
    //    when ONLY use the str (without the mov), we have already set the r3 <- #0 :/ //




    // Check if reg_sd is a source of a subsequent instruction //
    if(modify_prev_boolean){
      if(glob_effects_list->tail != NULL){
        // List of effects //
        for(ptr_aux = glob_effects_list->tail->prev; ptr_aux != NULL; ptr_aux = ptr_aux->prev){
          prev_effects_ptr = GETPOINTER(ptr_aux, effect_repr_t);
          // effects_ptr: the actual instruction | prev_effects_ptr: the subsequent instruction previously computed //
          if( !(effects_ptr->is_store) && (prev_effects_ptr->rs == reg_sd || prev_effects_ptr->rn == reg_sd) ){
            if(prev_effects_ptr->two_operands){
              if(effects_ptr->two_operands){

                prev_effects_ptr->extra_operation = effects_ptr->operation;
                if(prev_effects_ptr->use_inmediate){
                  if(effects_ptr->use_inmediate){
                    prev_effects_ptr->override = OVERRIDE_INM_INM;
                    prev_effects_ptr->rs = effects_ptr->rs;
                    prev_effects_ptr->extra_value = effects_ptr->value;
                  }
                  else{
                    prev_effects_ptr->override = OVERRIDE_INM_REG;
                    prev_effects_ptr->rs = effects_ptr->rs;
                    prev_effects_ptr->rn = effects_ptr->rn;
                  }
                }
                else{
                  if(effects_ptr->use_inmediate){

                    prev_effects_ptr->extra_value = effects_ptr->value;
                    if(prev_effects_ptr->rs == reg_sd ){
                      prev_effects_ptr->override = OVERRIDE_REG_INM_B;
                      prev_effects_ptr->rs = effects_ptr->rs;
                      //prev_effects_ptr->rn = prev_effects_ptr->rn;
                    }
                    else{
                      prev_effects_ptr->override = OVERRIDE_REG_INM_A;
                      //prev_effects_ptr->rs = prev_effects_ptr->rs;
                      prev_effects_ptr->rn = effects_ptr->rs;
                    }

                  }
                  else{

                    if(prev_effects_ptr->rs == reg_sd ){
                      prev_effects_ptr->override = OVERRIDE_REG_REG_B;
                      prev_effects_ptr->extra_value = prev_effects_ptr->rn;
                      prev_effects_ptr->rs = effects_ptr->rs;
                      prev_effects_ptr->rn = effects_ptr->rn;
                    }
                    else{
                      prev_effects_ptr->override = OVERRIDE_REG_REG_A;
                      //prev_effects_ptr->rs = prev_effects_ptr->rs;
                      prev_effects_ptr->rn = effects_ptr->rs;
                      prev_effects_ptr->extra_value = effects_ptr->rn;
                    }
                  }
                }

              }
              else{
                if(prev_effects_ptr->rs == reg_sd ){
                  prev_effects_ptr->override = OVERRIDE_SIMP;
                  prev_effects_ptr->rs = (effects_ptr->use_inmediate)? effects_ptr->value : effects_ptr->rs;
                }
                else if(prev_effects_ptr->rn == reg_sd ){
                  prev_effects_ptr->rn = (effects_ptr->use_inmediate)? effects_ptr->value : effects_ptr->rs;
                }
                if( (prev_effects_ptr->use_inmediate = effects_ptr->use_inmediate) ){
                  prev_effects_ptr->value = effects_ptr->value;
                }

              }
            }
            else{ //prev_effects_ptr : 1 operand
              if(effects_ptr->two_operands){

                prev_effects_ptr->two_operands = effects_ptr->two_operands;
                prev_effects_ptr->use_inmediate = effects_ptr->use_inmediate;
                prev_effects_ptr->rs = effects_ptr->rs;
                prev_effects_ptr->rn = effects_ptr->rn;
                prev_effects_ptr->operation = effects_ptr->operation;
                prev_effects_ptr->value = effects_ptr->value;

              }
              else{

                prev_effects_ptr->rs = (effects_ptr->use_inmediate)?  effects_ptr->value : effects_ptr->rs;
                if( (prev_effects_ptr->use_inmediate = effects_ptr->use_inmediate) )
                  prev_effects_ptr->value = effects_ptr->value;

              }
            }
          }
        }
      }
    }
    */



    //For all the gadgets
    memcpy(gadget_struct->Inputs, Inputs, (15 * sizeof(int)));
    memcpy(gadget_struct->Outputs, Outputs, (15 * sizeof(int)));

    if(check_gadget_len(node_ptr, MAX_GADGET_LENGTH)) break; /// 3 at the moment.......
  }
  // Delete the Effects which appears in pop{..., pc} because it overrides the register(s) //
  clearEffects(pop_regs, glob_effects_list);
  return;
}

// Insert with order //
void add_gadget_to_list(int score, struct Lnode *node, struct list *register_l){
  unsigned char inserted = 0;
  struct r_node_data *data;
  struct Lnode *ptr;
  int i;

  if(node != NULL && register_l != NULL){
    for(ptr = register_l->head, i = 0; ptr != NULL && i < MAX_REPO_GADGETS; ptr = ptr->next, i++){
      data = GETPOINTER(ptr, struct r_node_data);

      if(data->score < score){
        addNode_to_repo(score, node, register_l, ptr);
        inserted = 1;
        break;
      }
      else if(data->score == score){
        // Don't add
        inserted = 1;
        break;
      }
    }

    for(ptr = register_l->head, i = 0; ptr != NULL; ptr = ptr->next, i++);

    if(!inserted && i < MAX_REPO_GADGETS){
      addNode_to_repo(score, node, register_l, 0); //to the tail
    }

    while(i > MAX_REPO_GADGETS){
      deleteNode(register_l, register_l->tail);
      i--;
    }
  }
}

unsigned char writes_to_sp(struct Lnode *node_ptr){
  if(node_ptr != NULL){
    while(node_ptr->next != NULL) node_ptr = node_ptr->next; //'ret'
    return GETPOINTER(node_ptr, Gadget_t)->Outputs[13];
  }
  else
    return 0;
}

// Get the number of words (32 bits) of the frame of the 'ret' instruction //
int getWordCount(struct Lnode *node_ptr){
  int i, sum, *Outputs;

  if(node_ptr != NULL){
    while(node_ptr->next != NULL) node_ptr = node_ptr->next; //'ret'
    Outputs = GETPOINTER(node_ptr, Gadget_t)->Outputs;

    for(sum = 0, i = 0; i < 15; i++)
      if(Outputs[i]) sum++;

    return sum;
  }
  else
    return 0;
}

int evaluate(struct Lnode *gptr, int reg){
  struct Lnode *node_ptr = NULL;
  effect_repr_t *effects_ptr = NULL;
  Gadget_t *gadget_struct = NULL;
  int sum = 15;

  if(gptr != NULL){
    gadget_struct = GETPOINTER(gptr, Gadget_t);

    if(reg > 2){ //Auxiliars (reg: 1000)
      if(writes_to_sp(gptr)){
        return -1;
      }
      else
        return sum - getWordCount(gptr);
    }
    else if(reg >= 0){
      //r0, r1, r2
      sum -= getWordCount(gptr);

      if(gptr->next == NULL){ //'ret' node
        node_ptr = NULL;
      }
      else{
        // Check if the writers of r0 or r1 writes into r2 //
        if((reg == 0 || reg == 1) && gadget_struct->Outputs[2])
          return -1;

        //reuse of 'node_ptr'
        node_ptr = gadget_struct->pointer.effects_node;
        sum -= 2;
      }

      for(; node_ptr != NULL; node_ptr = node_ptr->prev){
        effects_ptr = GETPOINTER(node_ptr, effect_repr_t);

        if(effects_ptr->is_store){
          return -1;
        }
        else{
          // DATA INSTRUCTIONS //
          if(effects_ptr->override == OVERRIDE_NONE
            || effects_ptr->override == OVERRIDE_SIMP){
            if(reg == 0 || reg == 1){
              if(!effects_ptr->use_inmediate){
                if(!effects_ptr->two_operands)
                  sum += 2;
                if(effects_ptr->rs == 2)
                  sum -= 100;
              }
            }
            else if(reg == 2 && effects_ptr->rd == 2){ //For evaluate writes to r2
              if(effects_ptr->two_operands){
                if(effects_ptr->use_inmediate){ // reg & inm
                  if(effects_ptr->rs != 2){
                    sum += 2;
                  }
                  else{
                    sum -= 100;
                  }
                }
                else{ // reg & reg
                  if(effects_ptr->rs == 2 || effects_ptr->rn == 2){
                    sum -= 100;
                  }
                  else{
                    sum += 2;
                  }
                }
              }
              else{
                if(effects_ptr->use_inmediate){
                  if(effects_ptr->value == 0){
                    sum += 2;
                  }
                  else{
                    sum -= 1000;
                  }
                }
                else{ //register
                  sum += 4;
                }
              }
            }
            //FOR ALL CASES
            if(reg == 1 && effects_ptr->rd == 0 && effects_ptr->use_inmediate && !effects_ptr->two_operands){
              //We don't want the writer r1 contamines r0 (order: r2 -> r0 -> r1) //TODO to improve this mechanism (deleting the hardcoded order)
              return -1;
            }

            if(effects_ptr->rd == 13){
              return -1;
              //TODO improve this situation
              /*
              if((!effects_ptr->two_operands || !effects_ptr->use_inmediate)
                || effects_ptr->rs != 13){
                  sum -= 1000;
              }
              else{
                sum -= 4;
              }
              */
            }
          }
          else{ //OVERRIDE RESULTS
            //TODO for future improvements
            // at the moment, we reject this gadgets
            //TODO also to implement in [sm.c]
            return -1;
          }
        }
      }
      return sum;
    }
    else{ //Stores
      //TODO
      return sum;
    }
  }
  else{
    return -2;
  }
}



/*
 * Check if the following instructions are available:
 *  # mov r0, r4 (e1a00004) or any 'pop' which writes into r0
 *  # mov r1, r5 (e1a01005) or any 'pop' which writes into r1
 *  # write to r2
 *  # write to r7
 *  # str r3, [r4]
 *  # svc
 *  # Required inputs (i.e. r3, r4, r5, etc)
 *
 *  NOTE: if r2 is not properly set, the payload execution will probably work,
 *        but we build the payload just in case... (showing a warning)
 *        [ in the target process, the error code in r0 is 0xfffffff2 (-14) ]
 *
 *  Return codes:
 *    -1: Esential instruction(s) missing
 *    0:  All right
 *    1:  Write to r2 missing (payload execution depends on the register state)
 */
int check_key_instructions(){
  struct Lnode *gadget_ptr = NULL;
  struct Lnode *node_ptr = NULL;
//  struct Lnode *mov2_0_ptr = NULL;
  struct list *subList = NULL;
  Gadget_t *gadget_struct = NULL;
  instr_obj_32 *instruction_ptr = NULL;
  //uint32_t opcode_mov2_0 = get_opcode_data_instr(0xe, 1, OP_MOV, 0, 2, 0); //mov  r2, #0
  uint32_t opcode_mov04 = get_opcode_data_instr(0xe, 0, OP_MOV, 0, 0, 4); //mov r0, r4
  uint32_t opcode_mov15 = get_opcode_data_instr(0xe, 0, OP_MOV, 0, 1, 5); // mov r1, r5
  uint32_t opcode_str = get_opcode_mem_single_instr(0xe, 0, 1, 1, 0, 0, 0, 4, 3, 0); //str r3, [r4]
  int i, j, *Outputs;
  int return_code = 0;


  for(gadget_ptr = gadgets->head; gadget_ptr != NULL; gadget_ptr = gadget_ptr->next){ //List of gadgets
    subList = *GETPOINTER(gadget_ptr, struct list *); //Each gadget
    for(node_ptr = subList->tail; node_ptr != NULL; node_ptr = node_ptr->prev){
      gadget_struct = GETPOINTER(node_ptr, Gadget_t);
      Outputs = gadget_struct->Outputs;
      instruction_ptr = gadget_struct->instruction;

      // Best gadget for write r0 -> mov r0, r4 || pop //
      if(instruction_ptr->opcode == opcode_mov04
        || ( (node_ptr == subList->tail) && Outputs[0])){ // pop{r0, ..., pc} //
        i = evaluate(node_ptr, 0);
        if(i > 0){
          add_gadget_to_list(i, node_ptr, repository[0]);
        }

      }

      // Best gadget for write r1 -> mov r1, r5 || pop //
      else if(instruction_ptr->opcode == opcode_mov15
        || (node_ptr == subList->tail && Outputs[1])){ // pop{?, r1, ..., pc} //
        i = evaluate(node_ptr, 1);
        if(i > 0){
          add_gadget_to_list(i, node_ptr, repository[1]);
        }
      }

      // For writing in r2 //
      else if(Outputs[2]){
        i = evaluate(node_ptr, 2);
        if(i > 0){
          add_gadget_to_list(i, node_ptr, repository[2]);
        }
      }
      // str r3, [r4] //
      else if(instruction_ptr->opcode == opcode_str){
        i = evaluate(node_ptr, -1);
        if(i > 0)
          add_gadget_to_list(i, node_ptr, repository[3]);
      }


      // We only want 'ret' instructions for the auxiliar gadgets //
      else if(node_ptr == subList->tail){ //is a 'ret'
        i = evaluate(node_ptr, 1000);
        if(i > 0){
          for(j = 0; j < AUXILIAR_REGS-1; j++){ //r3 .. r12 + r14 //
            if(Outputs[j+3]){
              add_gadget_to_list(i, node_ptr, auxiliars_repo[j]);
            }
          }
          //r14
          if(Outputs[14]){
            add_gadget_to_list(i, node_ptr, auxiliars_repo[10]);
          }
        }
      }
    }
    if(check_gadget_len(node_ptr, MAX_GADGET_LENGTH)) break; /// 3 at the moment.......
  }

  if(repository[0]->head == NULL){ //write to r0
    fprintf(stderr, "[-] Missing instruction for write in register r0\n");
    return_code = -1;
  }
  if(repository[1]->head == NULL){ //write to r1
    fprintf(stderr, "[-] Missing instruction for write in register r1'\n");
    return_code = -1;
  }
  if(repository[2]->head == NULL){
    fprintf(stderr, "[-] Missing instruction for write in register r2\n");
    return_code = 1;
  }
  if(repository[3]->head == NULL){
    fprintf(stderr, "[-] Missing instruction 'str r3, [r4]'\n");
    return_code = -1;
  }

  if(auxiliars_repo[3-3]->head == NULL){
    fprintf(stderr, "[-] Missing instruction for write in register r3\n");
    return_code = -1;
  }
  if(auxiliars_repo[4-3]->head == NULL){
    fprintf(stderr, "[-] Missing instruction for write in register r4\n");
    return_code = -1;
  }
  if(auxiliars_repo[7-3]->head == NULL){
    fprintf(stderr, "[-] Missing instruction for write in register r7\n");
    return_code = -1;
  }

  // Finally we check for 'svc' instruction //
  key_instructions.svc = NULL;
  for(node_ptr = list_Instructions->head; node_ptr != NULL; node_ptr = node_ptr->next){
    instruction_ptr = GETPOINTER(node_ptr, instr_obj_32);
    if((instruction_ptr->opcode>>24) == 0xef){
      key_instructions.svc = instruction_ptr;
      break;
    }
  }
  if(key_instructions.svc == NULL){
    fprintf(stderr, "[-] Missing system call instruction (svc)\n");
    return_code = -1;
  }

  if(return_code >= 0){
    return check_inputs(return_code);
  }
  else{
    return return_code;
  }
}

unsigned char all_inputs_available(struct Lnode *register_list_node){
  unsigned char return_code = 1;
  int i, *Inputs;

  Inputs = GETPOINTER(register_list_node, Gadget_t)->Inputs;
  for(i = 0; i < AUXILIAR_REGS-1 && return_code; i++){
    if(Inputs[i+3])
      return_code = (auxiliars_repo[i]->head != NULL);
  }
  //r14
  if(Inputs[14])
    return_code = (auxiliars_repo[AUXILIAR_REGS-1]->head != NULL);

  return return_code;
}

// Recursive function for find auxiliar gadgets //
// Returns the pointer to the gadget //
struct Lnode *getInputs(struct list *list){
  struct Lnode *gadget;

  if(list == NULL || list->head == NULL){
    return NULL;
  }
  else{
    gadget = GETPOINTER(list->head, struct r_node_data)->node;
    if(all_inputs_available(gadget)){
      return gadget;
    }
    else{
      deleteNode(list, list->head);
      return getInputs(list);
    }
  }
}

int check_inputs(int r2_missing){
  struct Lnode *ptr;
  int i, return_code = r2_missing;

  if(r2_missing){
    fprintf(stderr, "[!] Payload execution will probably not work\n");
  }

  // Write r0
  ptr = getInputs(repository[0]);
  if(ptr == NULL){
    fprintf(stderr, "[-] Writers to r0 dependences not found\n");
    return_code = -1;
  }
  else{
    key_instructions.write_r0 = ptr;
  }

  // Write r1
  ptr = getInputs(repository[1]);
  if(ptr == NULL){
    fprintf(stderr, "[-] Writers to r1 dependences not found\n");
    return_code = -1;
  }
  else{
    key_instructions.write_r1 = ptr;
  }

  // Write r2
  if(!r2_missing){
    ptr = getInputs(repository[2]);
    if(ptr == NULL){
      fprintf(stderr, "[-] Writers to r2 dependences not found\n");
      return_code = -1;
    }
    else{
      key_instructions.write_r2 = ptr;
    }
  }

  // Store
  ptr = getInputs(repository[3]);
  if(ptr == NULL){
    fprintf(stderr, "[-] Writers to store dependences not found\n");
    return_code = -1;
  }
  else{
    key_instructions.str = ptr;
  }

  if(return_code >= 0){
    key_instructions.r_w_addr = readwriteSegm->p_vaddr;

    for(i = 0; i < AUXILIAR_REGS; i++){
      ptr = (auxiliars_repo[i] != NULL)? auxiliars_repo[i]->head : NULL;
      if(ptr != NULL){
        key_instructions.Inputs[i] = GETPOINTER(ptr, struct r_node_data)->node;
      }
    }
  }

  return return_code;
}

void freeRepository(){
  int i;

  for(i = 0; i < 4; i++){
    freeList(repository[i]);
  }
  for(i = 0; i < AUXILIAR_REGS; i++){
    freeList(auxiliars_repo[i]);
  }
}

// /!\ We assume global_repo is empty //
void createRepository(){
  int i;

  for(i = 0; i < 4; i++){
    repository[i] = createList(sizeof(struct r_node_data));
  }
  for(i = 0; i < AUXILIAR_REGS; i++){
    auxiliars_repo[i] = createList(sizeof(struct r_node_data));
  }
}

// Print the metadata //
void debug_all_gadgets(){
  struct Lnode *gadget_ptr = NULL;
  struct list *subList = NULL;

  for(gadget_ptr = gadgets->head; gadget_ptr != NULL; gadget_ptr = gadget_ptr->next){ //List of gadgets
    subList = *GETPOINTER(gadget_ptr, struct list *); //Each gadget
    printMetadata(subList->head);
  }
}

// Builds the chain of gadgets for the exploit //
int build_chain(){
  struct Lnode *gadget_ptr = NULL;
  struct list *subList = NULL;
  int check_result;

  if(gadgets->head != NULL){
    // GET the metadata and store in memory //
    for(gadget_ptr = gadgets->head; gadget_ptr != NULL; gadget_ptr = gadget_ptr->next){ //List of gadgets
        subList = *GETPOINTER(gadget_ptr, struct list *); //Each gadget
        getMetadata(subList);
    }

    createRepository();

    // Search for the key instructions //
    check_result = check_key_instructions();

    if(check_result >= 0){
      build_payload_bin_sh(check_result);
    }
    else{
      fprintf(stderr, "[Combo not found...]\n");
      freeRepository();
      return -1;
    }
    //debug_all_gadgets();
  }

  freeRepository();
  return 0;
}
