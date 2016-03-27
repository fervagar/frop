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
    the Program is not required to print an announcement.)

These requirements apply to the modified work as a whole.  If
identifiable sections of that work are not derived from the Program,
and can be reasonably considered independent and separate works in
themselves, then this License, and its terms, do not apply to those
sections when you distribute them as separate works.  But when you
distribute the same sections as part of a whole which is a work based
on the Program, the distribution of the whole must be on the terms of
this License, whose permissions for other licensees extend to the
entire whole, and thus to each and every part regardless of who wrote it.

Thus, it is not the intent of this section to claim rights or contest
your rights to work written entirely by you; rather, the intent is to
exercise the right to control the distribution of derivative or
collective works based on the Program.

In addition, mere aggregation of another work not based on the Program
with the Program (or with a work based on the Program) on a volume of
a storage or distribution medium does not bring the other work under
the scope of this License.

  3. You may copy and distribute the Program (or a work based on it,
under Section 2) in object code or executable form under the terms of
Sections 1 and 2 above provided that you also do one of the following:

    a) Accompany it with the complete corresponding machine-readable
    source code, which must be distributed under the terms of Sections
    1 and 2 above on a medium customarily used for software interchange; or,

    b) Accompany it with a written offer, valid for at least three
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

#include <elf.h>

// for substitution in the gadget metadata extraction [chain.c] //
#define OVERRIDE_NONE         0
#define OVERRIDE_SIMP         1
#define OVERRIDE_INM_INM      2 // both 'prev' and 'actual' uses an inmediate value //
#define OVERRIDE_INM_REG      3 // 'prev' use an inmediate but not 'actual' //
#define OVERRIDE_REG_INM_A    4 // 'actual' uses an inmediate value but not 'prev' (substitution after) //
#define OVERRIDE_REG_INM_B    5 // 'actual' uses an inmediate value but not 'prev' (substitution before) //
#define OVERRIDE_REG_REG_A    6 // both uses registers (4 registers - substitution after ) //
#define OVERRIDE_REG_REG_B    7 // both uses registers (4 registers - substitution before ) //
// If override > 1 => 3 operands //

#define MAGIC_VALUE           0x1fe
#define AUXILIAR_REGS         11 // r3 .. r12 + r14 //

#define BIN_HEX               0x6e69622f  // '/bin' //
#define SH_HEX                0x68732f2f  // '//sh' //

// max length of gadgets in getMetadata() //
#define MAX_GADGET_LENGTH 3 // Don't modify //

typedef enum { ALL_MODE, GADGETS_MODE, CHAIN_MODE /* , SEARCH_MODE */} program_mode_t;

typedef enum {
  INS_RET,
  INS_DATA,
  INS_MEM,
  INS_STR,
  INS_MUL,
  INS_INT,
  INS_NOP,
  INS_SWP,
  INS_BKT,
  INS_PSR,
  INS_BR,
  INS_COP,
  INS_CLZ,
  INS_UNDEF
} instr_type_t;

typedef enum {
  // Data Processing //
  OP_AND,
  OP_EOR,
  OP_SUB,
  OP_RSB,
  OP_ADD,
  OP_ADC,
  OP_SBC,
  OP_RSC,
  OP_TST,
  OP_TEQ,
  OP_CMP,
  OP_CMN,
  OP_ORR,
  OP_MOV,
  OP_BIC,
  OP_MVN,
  // Other //
  OP_POP,
} op_t;

typedef enum {
  LSL,
  LSR,
  ASR,
  ROR,
  RRX
} Shift_t;

typedef struct {
  uint8_t two_operands;           // Boolean //
  uint8_t use_inmediate;          // Boolean //
  uint8_t is_store;               // Boolean //
  uint8_t neg_offset;             // Boolean //
  uint8_t override;               // for substitution //
  uint8_t rd;
  uint8_t rs;
  uint8_t rn;
  op_t    operation;              // Operation of current instruction //
  int     value;                  // inmediate || offset //
  int     extra_value;            // for substitution and str offset //
  op_t    extra_operation;        // for substitution //
} effect_repr_t;

// 'instr_obj_32' represents the unit of a instruction & their info (32: arch bits) //
typedef struct {
    uint32_t addr;                // Instruction address //
    uint32_t opcode;              // Instruction opcode //
    uint32_t regs;                // Registers => High: Write | Low: Read //
    op_t operation;               // Operation with registers //
    instr_type_t instr_type;      // Instruction type //
    uint8_t use_inmediate;        // Check if it use inmediate value //
    uint8_t use_shift;            // Check if it use a shift //
    uint8_t reg_shift;            // Register to shift //
    int inmediate;                // Inmediate Value //
    Shift_t shift_type;           // What kind of shift //
    char string[200];             // Disassembled Instruction //
} instr_obj_32;

typedef struct {
  instr_obj_32 *instruction;
  union {
    struct list *effects_list;      // 'return' node (tail) of each sublist in 'gadgets' //
    struct Lnode *effects_node;     // other nodes //
  } pointer;
  int Inputs[15];
  int Outputs[15];
} Gadget_t;

typedef struct {
  struct Lnode *write_r0; // type Gadget_t //
  struct Lnode *write_r1; // type Gadget_t //
  struct Lnode *write_r2; // type Gadget_t //
  struct Lnode *str;      // type Gadget_t //
  struct Lnode *Inputs[AUXILIAR_REGS]; // r3 (idx: 0) .. r12 (idx: 9) && r14 (idx:10) //r3,r4,r7 surely required
  instr_obj_32 *svc;
  uint32_t r_w_addr;
} key_instructions_t;

typedef struct {
  uint32_t value; // Address or Value to the stack //
  struct Lnode *gadget; // type Gadget_t //
  char *strings[MAX_GADGET_LENGTH];
} payload_gadget_t;
