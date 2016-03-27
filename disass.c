// Fernando Vañó //
/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The licenses for most software are designed to take away your
freedom to share and change it.  By contrast, the GNU General Public
License is intended to guarantee your freedom to share and change free
software--to make sure the software is free for all its users.  This
General Public License applies to most of the Free Software
Foundation's software and to any other program whose authors commit to
using it.  (Some other Free Software Foundation software is covered by
the GNU Lesser General Public License instead.)  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
this service if you wish), that you receive source code or can get it
if you want it, that you can change the software or use pieces of it
in new free programs; and that you know you can do these things.

  To protect your rights, we need to make restrictions that forbid
anyone to deny you these rights or to ask you to surrender the rights.
These restrictions translate to certain responsibilities for you if you
distribute copies of the software, or if you modify it.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must give the recipients all the rights that
you have.  You must make sure that they, too, receive or can get the
source code.  And you must show them these terms so they know their
rights.

  We protect your rights with two steps: (1) copyright the software, and
(2) offer you this license which gives you legal permission to copy,
distribute and/or modify the software.

  Also, for each author's protection and ours, we want to make certain
that everyone understands that there is no warranty for this free
software.  If the software is modified by someone else and passed on, we
want its recipients to know that what they have is not the original, so
that any problems introduced by others will not reflect on the original
authors' reputations.

  Finally, any free program is threatened constantly by software
patents.  We wish to avoid the danger that redistributors of a free
program will individually obtain patent licenses, in effect making the
program proprietary.  To prevent this, we have made it clear that any
patent must be licensed for everyone's free use or not licensed at all.

  The precise terms and conditions for copying, distribution and
modification follow.

                    GNU GENERAL PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. This License applies to any program or other work which contains
a notice placed by the copyright holder saying it may be distributed
under the terms of this General Public License.  The "Program", below,
refers to any such program or work, and a "work based on the Program"
means either the Program or any derivative work under copyright law:
that is to say, a work containing the Program or a portion of it,
either verbatim or with modifications and/or translated into another
language.  (Hereinafter, translation is included without limitation in
the term "modification".)  Each licensee is addressed as "you".

Activities other than copying, distribution and modification are not
covered by this License; they are outside its scope.  The act of
running the Program is not restricted, and the output from the Program
is covered only if its contents constitute a work based on the
Program (independent of having been made by running the Program).
Whether that is true depends on what the Program does.

  1. You may copy and distribute verbatim copies of the Program's
source code as you receive it, in any medium, provided that you
conspicuously and appropriately publish on each copy an appropriate
copyright notice and disclaimer of warranty; keep intact all the
notices that refer to this License and to the absence of any warranty;
and give any other recipients of the Program a copy of this License
along with the Program.

You may charge a fee for the physical act of transferring a copy, and
you may at your option offer warranty protection in exchange for a fee.

  2. You may modify your copy or copies of the Program or any portion
of it, thus forming a work based on the Program, and copy and
distribute such modifications or work under the terms of Section 1
above, provided that you also meet all of these conditions:

    a) You must cause the modified files to carry prominent notices
    stating that you changed the files and the date of any change.

    b) You must cause any work that you distribute or publish, that in
    whole or in part contains or is derived from the Program or any
    part thereof, to be licensed as a whole at no charge to all third
    parties under the terms of this License.

    c) If the modified program normally reads commands interactively
    when run, you must cause it, when started running for such
    interactive use in the most ordinary way, to print or display an
    announcement including an appropriate copyright notice and a
    notice that there is no warranty (or else, saying that you provide
    a warranty) and that users may redistribute the program under
    these conditions, and telling the user how to view a copy of this
    License.  (Exception: if the Program itself is interactive but
    does not normally print such an announcement, your work based on
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
