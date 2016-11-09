
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
