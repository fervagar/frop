
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "datatypes.h"
#include "linkedlist.h"

// Stat of analyzed file //
struct stat statBuff;
// Pointer to the file mmap //
char *fileptr;
// Pointer to the end of this file //
char *file_endptr;
// ELF Header -> e_shoff : pos: 0x20; size: 4 bytes; //
// Points to the start of the Section Header Table. //
Elf32_Ehdr *elfHeader;
// Program Header Table //
Elf32_Phdr *pht;
// ReadWrite Segment //
Elf32_Phdr *readwriteSegm;
// Linked list of Executable and Readable Segments (Elf32_Phdr pointers) //
struct list *listExecSegm;
// Linked list of decoded instructions //
struct list *list_Instructions;
// List of lists... Each node is a list of instructions: //
// Each list contains pointers to the 'list_Instructions' nodes //
struct list *gadgets;
// Simple counter, for future uses //
unsigned int num_gadgets = 0;

// max length of gadgets //
int gadget_length;

// Functions implemented in 'disassfuncs.c' //
void disassemble(instr_obj_32 *inst_struct);
void setopcodetab();

// Functions implemented in 'chain.c' //
int build_chain();

inline int checkELF(){
    return *((int *)fileptr) == 0x464c457f;
}

inline int checkArch(){
    return ( *(fileptr + 0x12)  == 0x28);
}

// For free the dynamic memory of 'gadgets' list //
void freeGadgets(){
    struct Lnode *gadget_ptr = NULL;
    struct list *subList = NULL;

    if(gadgets->head != NULL){
        for(gadget_ptr = gadgets->head; gadget_ptr != NULL; gadget_ptr = gadget_ptr->next){
            subList = *GETPOINTER(gadget_ptr, struct list *);
            //free the 'effects' list (it's in the 'tail' node)
            if(subList->tail != NULL){
              freeList((GETPOINTER(subList->tail, Gadget_t))->pointer.effects_list);
            }
            freeList(subList);
        }
        freeList(gadgets);
    }
}

int setup(){

    setopcodetab();

    elfHeader = (Elf32_Ehdr *) fileptr; //Setting up the ELF Header struct 'elfHeader'
    // &elfHeader->e_ehsize should be less than the end //
    if( (void *) &elfHeader->e_ehsize >= (void *) file_endptr ) {
        fprintf(stderr, "This ELF file is not valid\n");
        return -1;
    }
    //sht = (Elf32_Shdr *) (fileptr + elfHeader->e_shoff); //setting up the SectionHeaderTable (could be 0!)
    if (elfHeader->e_phnum == 0){
        fprintf(stderr, "This file have not a Program Header Table\n");
        return -1;
    }
    else{
        pht = (Elf32_Phdr *) (fileptr + elfHeader->e_phoff); //setting up the ProgramHeaderTable (could be 0!)
        // elfHeader->e_phentsize holds the size in bytes of one entry in the program header table (pth)
        // there are elfHeader->e_phnum entries of elfHeader->e_phentsize each one
        // Program Header table's size :=> elfHeader->e_phentsize * elfHeader->e_phnum
        return 0;
    }
}

// It returns the number of executable segments //
int findSegments(struct list *list){
    int i, numExec = 0;
    struct Lnode *new_node;
    Elf32_Phdr *ptr;

    // We must avoid the Entry which describes the pht itself (if present) //
    for(i = 0, ptr = pht; i < elfHeader->e_phnum; i++, ptr++){
        if( (ptr->p_flags == (PF_X | PF_R)) && (ptr->p_offset != (void*)pht-(void*)fileptr)){
            new_node = createLnode(list);
            SETPOINTER(new_node, ptr);
            addTail(list, new_node);
            numExec++;
        }
        else if(ptr->p_flags == (PF_R | PF_W)){
          if (readwriteSegm == NULL){
            readwriteSegm = ptr;
          }
          else if(ptr->p_memsz > readwriteSegm->p_memsz ){
            readwriteSegm = ptr;
          }
          // Data Segment: readwriteSegm->p_vaddr //
          // (ELF offset: readwriteSegm->p_offset //
        }
    }
    if(readwriteSegm == NULL)
      return -1;
    else
      return numExec;
}

// Prints the instruction of a gadget //
void printGadget(struct list *gadget){
  struct Lnode *node_ptr = NULL;
  instr_obj_32 *instruction_ptr = NULL;

  node_ptr = gadget->head;
  if(node_ptr != NULL){
    instruction_ptr = GETPOINTER(node_ptr, Gadget_t)->instruction;
    printf(" 0x%08x: %s; ", instruction_ptr->addr, instruction_ptr->string);
    node_ptr = node_ptr->next;
  }
  for( ; node_ptr != NULL; node_ptr = node_ptr->next){
      instruction_ptr = GETPOINTER(node_ptr, Gadget_t)->instruction;
      printf(" %s; ", instruction_ptr->string);
  }
  printf("\n");
}

// Prints all the gadgets //
void printAllGadgets(){
    struct Lnode *gadget_ptr = NULL;
    struct list *subList = NULL;

    if(gadgets != NULL){
        for(gadget_ptr = gadgets->head; gadget_ptr != NULL; gadget_ptr = gadget_ptr->next){ //List of gadgets
            subList = *GETPOINTER(gadget_ptr, struct list *); //Each gadget
            printGadget(subList);
        }
    }
    //printf("Total: %d functional gadgets\n", num_gadgets);
}

inline unsigned char isReturn(instr_obj_32 *op){
  //return ( !( (strstr(instruction_ptr->string, "pop") == NULL) || (strstr(instruction_ptr->string, "r15") == NULL) ) ); //Morgan's law: if it's pop && r15 return true
  return (op->instr_type == INS_RET) && ((op->opcode)>>29 == 7); //without condition;
}

inline unsigned char isHeadOfGadget(instr_obj_32 *op){
  return ((op->instr_type == INS_RET) || (op->instr_type == INS_BR) || (op->instr_type == INS_UNDEF));
}

inline unsigned char isValid(instr_obj_32 *op){
  return (
    ( (op->instr_type == INS_DATA)
//    || (op->instr_type == INS_MUL)
    || (op->instr_type == INS_INT)
    || (op->instr_type == INS_NOP)
    // Store Pre Indexing AND Inmediate Offset (Register offset NOT valid)//
    || ((op->instr_type == INS_STR) && (op->opcode & 0x01000000) && (op->use_inmediate)) )
      && ((op->opcode)>>29 == 7) );
}

// If the length is >= 'n' it returns 1; 0 otherwise //
inline unsigned char check_gadget_len(struct Lnode *ptr, int n){
  if(ptr == NULL || n < 0) return (n <= 0);
  else return check_gadget_len(ptr->next, n - 1);
}

// Builds the 'gadgets' list as from the 'list_Instructions' //
void search_gadgets(){
  unsigned char building = 0;
  struct list *new_gadget = NULL;
  struct Lnode *node_ptr = NULL; //points to nodes of 'list_Instructions'
  struct Lnode *new_instr_node = NULL; //points to nodes of 'list_Instructions'
  struct Lnode *new_gadget_node = NULL; //points to nodes of 'gadgets'
  instr_obj_32 *instruction_ptr = NULL;
  Gadget_t *gadget_struct = NULL;

  if(list_Instructions->tail != NULL){
    for(node_ptr = list_Instructions->tail; node_ptr != NULL; node_ptr = node_ptr->prev){
      instruction_ptr = GETPOINTER(node_ptr, instr_obj_32);

      if(building){ // We are in the middle of a gadget
        if(isHeadOfGadget(instruction_ptr) || (instruction_ptr->use_shift)
        || !isValid(instruction_ptr) || /* write into r15 */ (instruction_ptr->regs & 0x80000000)){
          building = 0;
          // Adding the builded gadget to the list of gadgets //
          addHead(gadgets, new_gadget_node);
          new_gadget_node = NULL;
          //In case this node is a 'ret'
          if(isReturn(instruction_ptr) && node_ptr != NULL && node_ptr->next != NULL){
            node_ptr = node_ptr->next; //Loop in the 'ret' again for create a node
          }
        }
        else if(isValid(instruction_ptr)){
          new_instr_node = createLnode(new_gadget);
          gadget_struct = GETPOINTER(new_instr_node, Gadget_t);
          gadget_struct->instruction = instruction_ptr;
          addHead(new_gadget, new_instr_node);
          num_gadgets++;
          //////////////////////////////////////////////////
          // Check if we have the number of instructions given in 'gadget_length' //
          if(check_gadget_len(new_instr_node, gadget_length)){
            building = 0;
            // Adding the builded gadget to the list of gadgets //
            addHead(gadgets, new_gadget_node);
            new_gadget_node = NULL;
          }
        }
      }
      else{ //Searching for 'return' instructions
        if(isReturn(instruction_ptr)){
          // Creating new node of list 'gadgets' //
          new_gadget_node = createLnode(gadgets);
          new_gadget = createList(sizeof(Gadget_t)); // List of Gadget_t nodes
          SETPOINTER(new_gadget_node, new_gadget);
          // Adding the 'return' to the gadget //
          new_instr_node = createLnode(new_gadget);
          gadget_struct = GETPOINTER(new_instr_node, Gadget_t);
          gadget_struct->instruction = instruction_ptr;
          addHead(new_gadget, new_instr_node);
          num_gadgets++;

          if(gadget_length == 1){
            //building = 0;
            // Adding the builded gadget to the list of gadgets //
            addHead(gadgets, new_gadget_node);
            new_gadget_node = NULL;
          }
          else{
            building = 1;
          }
        }
      }
    }
    // Checking if the first instruction is not a isHeadOfGadget //
    if(building){
      addHead(gadgets, new_gadget_node);
    }
  }
}

// Builds the 'list_Instructions' list as from the segments //
void decode_instructions(Elf32_Phdr *segm){
    unsigned int i, addr;
    int *ptr;
    instr_obj_32 *inst_struct = NULL;
	  struct Lnode *new_node = NULL;

    ptr = (int *)(fileptr + segm->p_offset);
    addr = segm->p_vaddr;
    for (i = 0; i < segm->p_filesz/4; i++, ptr++, addr += 4){
      new_node = createLnode(list_Instructions);
      inst_struct = GETPOINTER(new_node, instr_obj_32);

      inst_struct->addr = addr;
      inst_struct->opcode = *ptr;
      disassemble(inst_struct);
		  addTail(list_Instructions, new_node);
    }
    return;
}

inline void printi(instr_obj_32 *inst_struct){
  printf(" %08x:\t%08x\t%s\n", inst_struct->addr, inst_struct->opcode, inst_struct->string);
  return;
}

// Prints the entire list of instructions //
void printInstructions(){
  struct Lnode *node_ptr = NULL;
	instr_obj_32 *instruction = NULL;

  for(node_ptr = list_Instructions->head; node_ptr != NULL; node_ptr = node_ptr->next){
    instruction = GETPOINTER(node_ptr, instr_obj_32);
    printi(instruction);
	}
  printf("\n");
    return;
}

void run(program_mode_t mode){
    struct Lnode *segment_node;
    Elf32_Phdr *ptr;

    for(segment_node = listExecSegm->head; segment_node != NULL; segment_node = segment_node->next){
        ptr = *GETPOINTER(segment_node, Elf32_Phdr *);
        decode_instructions(ptr);
    }
    // Find gadgets //
    search_gadgets();

    switch(mode){
      case ALL_MODE:
        // Show the list of gadgets //
        printAllGadgets();
        // Build a chain //
        build_chain();
        //TODO
        break;
      case GADGETS_MODE:
        // Show the list of gadgets //
        printAllGadgets();
        break;
      case CHAIN_MODE:
        // Build a chain //
        build_chain();
        //TODO
        break;
      /*
	  //FOR FUTURE IMPROVEMENTS:
	  case SEARCH_MODE:
        prompt_search();
        break;
      case DISASS_MODE:
      // Disassemble File
      //printInstructions();
      */
    }
    return;
}

int disass(program_mode_t mode, char *filename){
    int fd, num_segments, exitError = 0;

    if ((fd = open(filename, O_RDONLY)) == -1){
        printf("I could not open the file %s\n", filename);
        return -1;
    }

    if (fstat(fd, &statBuff)) {
        printf("I could not stat the file %s\n", filename);
        close(fd);
        return -1;
    }

    if ((fileptr = mmap(0, statBuff.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED){
        printf("I could not mmap the file %s\n", filename);
        close(fd);
        return -1;
    }
    file_endptr = fileptr + statBuff.st_size;

    if (!checkELF()){
        printf("The file \"%s\" is not an ELF file...\n", filename);
        exitError++;
        goto LEAVE;
    }

    if (!checkArch()){
        printf("Bad architecture\n");
        exitError++;
        goto LEAVE;
    }

    if(setup() == -1){
      exitError++;
      goto LEAVE;
    }

    listExecSegm = createList(sizeof(Elf32_Phdr *)); //the size of the payload is the size of the *Elf32_Phdr type
    if ( (num_segments = findSegments(listExecSegm)) <= 0){
      if(num_segments == 0){
        fprintf(stderr, "This file have not any Executable Segment in their code!\n");
      }
      else{
        fprintf(stderr, "This file have not any Read/Write Segment!\n");
      }
      freeList(listExecSegm);
      exitError++;
      goto LEAVE;
    }

    gadgets = createList(sizeof(struct list *));
	  list_Instructions = createList(sizeof(instr_obj_32)); //the size of the payload is the size of the 'instr_obj_32' structure

    run(mode);

LEAVE:
    munmap(fileptr, statBuff.st_size);
    close(fd);
    if(exitError == 0){
      freeGadgets();
      freeList(list_Instructions);
      freeList(listExecSegm);
      return 0;
    }
    else{
      return -1;
    }
}
