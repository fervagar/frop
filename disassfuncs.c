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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "datatypes.h"

static char *opcodetab[16][256];

//cmpstr: compare the 'j' first chars -> cmpstr("and", "ands", 3) == true:
inline int cmpstr(char *str1, char *str2, int j){
    int i;
    for(i = 0; i < j; i++)
        if(str1[i] != str2[i]) return 0;
        else if (str1[i] == 0x0) return 1;
    return 1;
}

// Rotate left //
unsigned int rotl(const unsigned int value, int shift){
    if ((shift &= sizeof(value)*8 - 1) == 0)
        return value;
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

// Rotate right //
unsigned int rotr(const unsigned int value, int shift){
    if ((shift &= sizeof(value)*8 - 1) == 0)
        return value;
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

// ARM Inmediate Encoding  //
unsigned int encode(const unsigned int value){
  unsigned int i, j;

  for(i = 0; i < 16; i++){
    j = rotl(value, 2*i);
    if(j < 256){
      return ((i << 8) | j);
    }
  }
  return MAGIC_VALUE;
}

//unsigned int not(unsigned int n) { return n ^ -1; }

unsigned int calcAddrB(unsigned int offset){

    offset *= 4;    //2 left shift
    if(offset & 0x02000000) //sign extend to 32 bits
        offset |= 0xfc000000;
    else offset &= 0x03ffffff;

    return offset+8; //the assembler substract 8 in the coding
}

// /!\ Carefull //
char *rename_pop_registers(char *dest, const char *src, int dest_size){
    int i, j, regs;
    char *eq[6] = {"sl", "fp", "ip", "sp", "lr", "pc"};
    char *pos[6];
    unsigned char pos2[6];
    char  *__restrict tmp1;
    char  *__restrict tmp2;
    char *ptr;

    for(i = 0; i < dest_size; i++)
        dest[i] = '\0';

    tmp1 =  (char *) malloc(10);
    tmp2 =  (char *) malloc(10);

    for(i = 10, j = 0, regs = 0; i <= 15; i++){
        sprintf(tmp1, "r%d", i);
        ptr = strstr(src, tmp1);
        if(ptr != NULL){
            pos[regs++] = ptr;
            pos2[j++] = i-10;
        }
    }
    if(regs == 0){
        free(tmp1);
        free(tmp2);
        return dest;
    }
    if(regs < 6)
        pos[regs] = pos[regs-1] + 3;

    strncpy(dest, src, pos[0]-src);
    for(i = 0; i < regs; i++){
        ptr = pos[i]+3;
        strcat(dest, eq[pos2[i]]);
        while(ptr < pos[i+1]){
            sprintf(tmp2, "%c", *ptr++);
            strcat(dest, tmp2);
        }
    }
    while(*ptr != 0){
        sprintf(tmp2, "%c", *ptr++);
        strcat(dest, tmp2);
    }
    free(tmp1);
    free(tmp2);
    return dest;
}

void disassemble(instr_obj_32 *inst_struct){
    int i, j;
	  //uint32_t addr;
    op_t *operation;
    instr_type_t *instr_type;
    uint32_t opcode, *regs;
    uint8_t *use_inmediate, *use_shift;
    uint8_t *reg_shift;
    int *inmediate;
    Shift_t *shift_type;
    uint32_t reg1, reg2, reg3, reg4;
    char *inst;
    char instr_temp[200]; // /!\ //
    char *condfield[16] = {"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", ""};
    char *dataprocinst[20] =
        {"and","eor","sub","rsb","add","adc","sbc","rsc",
        "tst","teq","cmp","cmn","orr","mov","bic","mvn",
        "qadd","qsub","qdadd","qdsub"};
    char *branchinst[3] = {"bl","bx", "blx"};
    char *loadstoreinst[4] = {"ldr", "str", "ldm", "stm"};
    char *coprocinst[5] = {"cdp", "ldc", "stc", "mrc", "mcr"};
    char tmp_[5] = "\0\0\0\0\0"; //auxiliar var used to patch the bit S and cond field in shift instructions
    /*
     a = (opcode>>4) & 0xF;
     b = (opcode>>20) & 0xFF;
    */
    //addr = inst_struct->addr;
    opcode = inst_struct->opcode;
    regs = &inst_struct->regs;
    *regs = 0;
    operation = &inst_struct->operation;
    instr_type = &inst_struct->instr_type;
    use_inmediate = &(inst_struct->use_inmediate);
    use_shift = &inst_struct->use_shift;
    *use_shift = 0;
    *use_inmediate = 0;
    inmediate = &inst_struct->inmediate;
    *inmediate = 0;
    reg_shift = &inst_struct->reg_shift;
    shift_type = &inst_struct->shift_type;
    inst = inst_struct->string;
    sprintf(inst, "%s%s ", opcodetab[(unsigned int)((opcode>>4) & 0xf)][(unsigned int)((opcode>>20) & 0xff)], condfield[(opcode>>28) & 0xf]);

    //Check if is a Software Interrupt instruction
    if(cmpstr(inst, "svc", 3)){
        *instr_type = INS_INT;
        //Inmediate value is ignored by processor
        sprintf(instr_temp, " 0x%02x", (opcode & 0xffffff));
        strcat(inst, instr_temp);
    }

    //Check if is a Breakpoint instruction
    if(cmpstr(inst, "bkpt", 4)){
        *instr_type = INS_BKT;
        sprintf(instr_temp, " 0x%02x", ((opcode>>4) & 0xfff0)+(opcode & 0xf));
        strcat(inst, instr_temp);
        return;
    }

    //Check if is a 'Count leading zeroes' instruction
    if(cmpstr(inst, "clz", 3)){
        *instr_type = INS_CLZ;
        reg1 = ((opcode>>12) & 0xf);
        reg2 = (opcode & 0xf);
        *regs |= ( ((1<<reg1) << 16) | (1<<reg2) );
        sprintf(instr_temp, " r%d, r%d", reg1, reg2);
        strcat(inst, instr_temp);
        return;
    }

    //Check if is a Swap instruction
    if(cmpstr(inst, "swp", 3)){
        *instr_type = INS_SWP;
        sprintf(instr_temp, " r%d, r%d, [r%d]", ((opcode>>12) & 0xf), (opcode & 0xf), ((opcode>>16) & 0xf));
        strcat(inst, instr_temp);
    }

    //Check if is a PSR instruction
    if(cmpstr(inst, "msr", 3) || cmpstr(inst, "mrs", 3)){
        *instr_type = INS_PSR;
    }

    //Check if is an invalid instruction
    if(cmpstr(inst, "in", 2)){
        *instr_type = INS_UNDEF;
    }
    //Check if is a data processing instruction
    for(i = 0; i < 20; i++) if(cmpstr(inst, dataprocinst[i], 3)) break;
    if(i < 20){ //Is a Data Processing Instrucion
        *operation = ((opcode>>21) & 0xf);
        if(*operation >= OP_TST && *operation <= OP_CMN){
          *instr_type = INS_NOP; // Is like a NOP for our purpose //
        }
        else{
          *instr_type = INS_DATA;
        }
        if( cmpstr(inst, "qadd", 3) || cmpstr(inst, "qdadd", 3)
          || cmpstr(inst, "qsub", 3) || cmpstr(inst, "qdsub", 3)){
          reg1 = ((opcode>>12) & 0xf);
          reg2 = (opcode & 0xf);
          reg3 = ((opcode>>16) & 0xf);
          *regs |= ( ((1<<reg1) << 16) | (1<<reg2) | (1<<reg3) );
          sprintf(instr_temp, " r%d, r%d, r%d", reg1, reg2, reg3);
          strcat(inst, instr_temp);
          return;
        }
        //Destination Register & 1st Operand Register (if is a test instruction or a move instruction, we omit the first register)
        else if(cmpstr(inst, "tst", 3)
        || cmpstr(inst, "mov", 3)
        || cmpstr(inst, "mvn", 3)
        || cmpstr(inst, "teq", 3)
        || cmpstr(inst, "cmp", 3)
        || cmpstr(inst, "cmn", 3) )
        {
            if( (((opcode>>20) & 0xff) == 0x1a)
                || (((opcode>>20) & 0xff) == 0x1b)
                || (((opcode>>20) & 0xff) == 0x3a)
                || (((opcode>>20) & 0xff) == 0x3b)
                || (((opcode>>20) & 0xff) == 0x1e)
                || (((opcode>>20) & 0xff) == 0x1f)
                || (((opcode>>20) & 0xff) == 0x3e)
                || (((opcode>>20) & 0xff) == 0x3f) )
            { // Is a MOV or MVN -> destination in nibble 15-12
              reg1 = ((opcode>>12) & 0xf);
            }else{
              reg1 = ((opcode>>16) & 0xf);
           }
           *regs |= (1<<reg1) << 16;
           sprintf(instr_temp, " r%d, ", reg1);
        }
        else{ //All the other data instructions
          reg1 = ((opcode>>12) & 0xf);
          reg2 = ((opcode>>16) & 0xf);
          *regs |= ( ((1<<reg1) << 16) | (1<<reg2) );
          sprintf(instr_temp, " r%d, r%d, ", reg1, reg2);
        }
        strcat(inst, instr_temp);

        //Check if bit 25 is 1 -> operand 2 is an inmediate | if it is 0 -> register or shift
        if( (opcode>>25) & 0x1 ){ //Inmediate
          *use_inmediate = 1;
          *inmediate = rotr( (opcode & 0xff), ((opcode>>7) & 0x1f) );
          sprintf(instr_temp, "#%d", *inmediate);
          strcat(inst, instr_temp);
        }else{ //Register / shift
            if( (opcode>>4) & 0xff ){ //Shift
                if( ((opcode>>20) & 0xff) == 0x1b )
                        sprintf(tmp_, "s");
                switch( (opcode>>28) & 0xf ){
                    case 0:
                        strcat(tmp_, "eq");
                        break;
                    case 1:
                        strcat(tmp_, "ne");
                        break;
                    case 2:
                        strcat(tmp_, "cs");
                        break;
                    case 3:
                        strcat(tmp_, "cc");
                        break;
                    case 4:
                        strcat(tmp_, "mi");
                        break;
                    case 5:
                        strcat(tmp_, "pl");
                        break;
                    case 6:
                        strcat(tmp_, "vs");
                        break;
                    case 7:
                        strcat(tmp_, "vc");
                        break;
                    case 8:
                        strcat(tmp_, "hi");
                        break;
                    case 9:
                        strcat(tmp_, "ls");
                        break;
                    case 10:
                        strcat(tmp_, "ge");
                        break;
                    case 11:
                        strcat(tmp_, "lt");
                        break;
                    case 12:
                        strcat(tmp_, "gt");
                        break;
                    case 13:
                        strcat(tmp_, "le");
                        break;
                }
                if( ((opcode>>21) & 0xf) == 0xd  ){ //If is a mov... translate it to a shift instruction
                    *use_shift = 1;
                    if ( (opcode>>4) & 0x1 ){ //Register
                        reg1 = ((opcode>>12) & 0xf);
                        reg2 = (opcode & 0xf);
                        reg3 = ((opcode>>8) & 0xf);
                        *regs |= ( ((1<<reg1) << 16) | (1<<reg2) | (1<<reg3) );
                        switch( (opcode>>4) & 0xf ){
                            case 0 :
                            case 1 :
                            case 8 :
                            case 9 :
                              sprintf(inst, "%s%s r%d, r%d, r%d", "lsl", tmp_, reg1, reg2, reg3);
                              break;
                            case 2 :
                            case 3 :
                            case 10 :
                            case 11 :
                              sprintf(inst, "%s%s r%d, r%d, r%d", "lsr", tmp_, reg1, reg2, reg3);
                              break;
                            case 4 :
                            case 5 :
                            case 12 :
                            case 13 :
                              sprintf(inst, "%s%s r%d, r%d, r%d", "asr", tmp_, reg1, reg2, reg3);
                              break;
                            case 6 :
                            case 7 :
                            case 14 :
                            case 15 :
                              sprintf(inst, "%s%s r%d, r%d, r%d", "ror", tmp_, reg1, reg2, reg3);
                              break;
                        }
                        return;
                    }
                    else{ //Inmediate
                        if( ((opcode>>7) &0x1f) == 0 ){ //Check if is a RRX
                          reg1 = ((opcode>>12) & 0xf);
                          reg2 = (opcode & 0xf);
                          *regs |= ( ((1<<reg1) << 16) | (1<<reg2) );
                          sprintf(inst, "%s%s r%d, r%d", "rrx", tmp_, reg1, reg2);
                        }
                        else{ //Is not a RRX instruction
                            reg1 = ((opcode>>12) & 0xf);
                            reg2 = (opcode & 0xf);
                            reg3 = ((opcode>>7) &0x1f);
                            *regs |= ( ((1<<reg1) << 16) | (1<<reg2) | (1<<reg3) );
                            switch( (opcode>>4) & 0xf ){
                                case 0 :
                                case 1 :
                                case 8 :
                                case 9 :
                                  sprintf(inst, "%s%s r%d, r%d, #%d", "lsl", tmp_, reg1, reg2, reg3);
                                  break;
                                case 2 :
                                case 3 :
                                case 10 :
                                case 11 :
                                  sprintf(inst, "%s%s r%d, r%d, #%d", "lsr", tmp_, reg1, reg2, reg3);
                                  break;
                                case 4 :
                                case 5 :
                                case 12 :
                                case 13 :
                                  sprintf(inst, "%s%s r%d, r%d, #%d", "asr", tmp_, reg1, reg2, reg3);
                                  break;
                                case 6 :
                                case 7 :
                                case 14 :
                                case 15 :
                                  sprintf(inst, "%s%s r%d, r%d, #%d", "ror", tmp_, reg1, reg2, reg3);
                                  break;
                            }
                        }
                    }
                    return;
                }//end translate
                else { //It is not a mov but it have a shift
                    reg3 = (opcode & 0xf);
                    *regs |= (1<<reg3);
                    switch( (opcode>>4) & 0xf ){
                      //If bit 4 is 0: shift with inmediate
                      //If bit 4 is 1: shift with register
                        case 0 :
                        case 8 :
                          *use_shift = 1;
                          *use_inmediate = 1;
                          *inmediate = ((opcode>>7) & 0x1f);
                          sprintf(instr_temp, "r%d, lsl #%d", reg3, *inmediate);
                          break;
                        case 1 :
                        case 9 :
                          *use_shift = 1;
                          reg4 = (opcode>>8) & 0xf;
                          *regs |= (1<<reg4);
                          *reg_shift = reg4;
                          *shift_type = LSL;
                          sprintf(instr_temp, "r%d, lsl r%d", reg3, reg4);
                          break;

                        case 2 :
                        case 10 :
                          *use_shift = 1;
                          *use_inmediate = 1;
                          *inmediate = ((opcode>>7) & 0x1f);
                          sprintf(instr_temp, "r%d, lsr #%d", reg3, *inmediate);
                          break;
                        case 3 :
                        case 11 :
                          *use_shift = 1;
                          reg4 = (opcode>>8) & 0xf;
                          *regs |= (1<<reg4);
                          *reg_shift = reg4;
                          *shift_type = LSR;
                          sprintf(instr_temp, "r%d, lsr r%d", reg3, reg4);
                          break;

                        case 4 :
                        case 12 :
                          *use_shift = 1;
                          *use_inmediate = 1;
                          *inmediate = ((opcode>>7) & 0x1f);
                          sprintf(instr_temp, "r%d, asr #%d", reg3, *inmediate );
                          break;
                        case 5 :
                        case 13 :
                          *use_shift = 1;
                          reg4 = (opcode>>8) & 0xf;
                          *regs |= (1<<reg4);
                          *reg_shift = reg4;
                          *shift_type = ASR;
                          sprintf(instr_temp, "r%d, asr r%d", reg3, reg4);
                          break;

                        case 6 :
                        case 7 :
                        case 14 :
                        case 15 :
                            if( ((opcode>>7) & 0x1f) == 0 ){
                                *shift_type = RRX;
                                sprintf(instr_temp, "r%d, rrx", reg3);
                            }
                            else{
                                if( ((opcode>>4) & 0x1) == 0 ){
                                  *use_shift = 1;
                                  *use_inmediate = 1;
                                  *inmediate = ((opcode>>7) & 0x1f);
                                  sprintf(instr_temp, "r%d, ror #%d", reg3, *inmediate);
                                }
                                else{
                                  *use_shift = 1;
                                  reg4 = (opcode>>8) & 0xf;
                                  *regs |= (1<<reg4);
                                  *reg_shift = reg4;
                                  *shift_type = ROR;
                                  sprintf(instr_temp, "r%d, ror r%d", reg3, reg4);
                                }
                            }
                            break;
                    }
                    strcat(inst, instr_temp);
                }
            } //end Shift
            else{ //Without shift / maybe is a NOP
                if( (((opcode>>28) & 0xf) == 0xe) && (!((opcode>>12) & 0xf)) && (!(opcode & 0xf)) && ((opcode>>23) & 0x3)){ //is a NOP
                  *regs = 0;
                  *instr_type = INS_NOP;
                  sprintf(inst, "%s", "nop");
                }else{ //Data processing instruction without a shift
                  reg3 = (opcode & 0xf);
                  *regs |= (1<<reg3);
                  sprintf(instr_temp, "r%d", reg3);
                  strcat(inst, instr_temp);
                }
            }
        }
    }//end Data Processing Instrucion
    ///*************************************************************************
    //Check if is a branch instruction
    for(i = 0; i < 3; i++) if(cmpstr(inst, branchinst[i], 2)) break;
    if(i < 3 || *inst == 'b'){ // -> bl || bx || blx || b
        *instr_type = INS_BR;

        return;
    }

    /*
    //FOR FUTURE IMPROVEMENTS:
    for(i = 0; i < 3; i++) if(cmpstr(inst, branchinst[i], 2)) break;
    if(i < 3 || *inst == 'b'){
        *instr_type = INS_BR;

        if(*inst == 'b' || cmpstr(inst, "bl", 2)){
            //// Can be a BLX...... and is the same field [0xe][0xaf]
            //sprintf(instr_temp, "  %x <...>", calcAddrB(opcode) + addr);
            sprintf(instr_temp, " %x", calcAddrB(opcode) + addr);
            strcat(inst, instr_temp);
        }
        else if(cmpstr(inst, "bx", 2)){
            //...
        }
        return;
    }
    */

    // Multiply Long and Multiply-Accumulate Long (MULL,MLAL)
    if(cmpstr(inst, "mull", 4)
        || cmpstr(inst+1, "mull", 4)
        || cmpstr(inst, "mlal", 4)
        || cmpstr(inst+1, "mlal", 4)
    ){
        *instr_type = INS_MUL;
        reg1 = ((opcode>>12) & 0xf);
        reg2 = ((opcode>>16) & 0xf);
        reg3 = (opcode & 0xf);
        reg4 = ((opcode>>8) & 0xf);
        *regs |= ( ((1<<reg1) << 16) | (1<<reg2) | (1<<reg3) | (1<<reg4) );
        sprintf(instr_temp, " r%d, r%d, r%d, r%d", reg1, reg2, reg3, reg4);
        strcat(inst, instr_temp);
    }
    // Multiply and Multiply-Accumulate (MUL, MLA)
    else if(cmpstr(inst, "mul", 3)
        || cmpstr(inst+1, "mul", 3)
        || cmpstr(inst, "mla", 3)
        || cmpstr(inst+1, "mla", 3)
    ){
        // MUL and SMULL have 3 regs : //
        // if the 21th bit is unset and the 4th bit is set : MUL //
        // if the 21th bit is set and the 4th bit is unset : SMUL //
        *instr_type = INS_MUL;
        reg1 = ((opcode>>16) & 0xf);
        reg2 = (opcode & 0xf);
        reg3 = ((opcode>>8) & 0xf);
        *regs |= ( ((1<<reg1) << 16) | (1<<reg2) | (1<<reg3) );

        if ( ( *(inst+1) == 'u' || *(inst+2) == 'u' ) &&
            ((opcode>>21) & 0x1) ^ ((opcode>>4) & 0x1) ){ //MUL or SMUL -> 3 regs
              sprintf(instr_temp, " r%d, r%d, r%d", reg1, reg2, reg3);
        }
        else{ //4 regs
          reg4 = ((opcode>>12) & 0xf);
          *regs |= (1<<reg3);
          sprintf(instr_temp, " r%d, r%d, r%d, r%d", reg1, reg2, reg3, reg4);
        }
        strcat(inst, instr_temp);
    }

    //Check if is a CoProcessor instruction
    for(i = 0; i < 5; i++) if(cmpstr(inst, coprocinst[i], 3)) break;
    if(i < 5){
        *instr_type = INS_COP;
    }

    //Check if is a load-store instruction
    for(i = 0; i < 4; i++) if(cmpstr(inst, loadstoreinst[i], 3)) break;
    if(i < 4){
        *instr_type = INS_MEM;
        if(cmpstr(inst, "ldrh", 4) || cmpstr(inst, "strh", 4) || cmpstr(inst, "ldrs", 4) ){
            // In this case, we only consider Store instructions (read/write meaning 'different') //
            reg1 = ((opcode>>12) & 0xf);
            reg2 = ((opcode>>16) & 0xf);
            *regs |= ( (1<<reg1) | ((1<<reg2) << 16) );
            *reg_shift = reg2; // In case it is a pre/post indexing //
            sprintf(instr_temp, " r%d, [r%d", reg1, reg2);
            strcat(inst, instr_temp);
            if(cmpstr(inst, "str", 3) && (opcode>>29 == 7)){ //without condition
              *instr_type |= INS_STR;
            }
            *use_inmediate = ((opcode>>22) & 0x1);
            if(!(*use_inmediate)){   // Register offset
                reg3 = (opcode & 0xf);
                *regs |= ((1<<reg3) << 16 );
                if(((opcode>>23) & 0x1)){ //add offset to base

                    if(opcode & 0x01000000){ // Pre indexing
                        sprintf(instr_temp, ", r%d]", reg3);
                    }
                    else{ // Post indexing
                      sprintf(instr_temp, "], r%d", reg3);
                    }
                }
                else{   //substract offset from base
                    if(opcode & 0x01000000){
                        sprintf(instr_temp, ", -r%d]", reg3);
                    }
                    else{
                        sprintf(instr_temp, "], -r%d", reg3);
                    }
                }
                strcat(inst, instr_temp);
            }
            else{ //Inmediate offset
                *inmediate = ((opcode >> 4) & 0xf0) + (opcode & 0xf); //Concatenated offset

                if(!((opcode>>23) & 0x1)){ //substract offset from base
                  *inmediate *= -1;
                }
                if(opcode & 0x01000000){ // Pre indexing
                    if(*inmediate){
                      sprintf(instr_temp, ", #%d]", *inmediate);
                    }
                    else{
                      sprintf(instr_temp, "]");
                    }
                }
                else {                    // Post indexing
                    if(*inmediate){
                      sprintf(instr_temp, "], #%d", *inmediate);
                    }
                    else{
                      sprintf(instr_temp, "]");
                    }
                }
                strcat(inst, instr_temp);
            }
        }
        // ------------
        else if(cmpstr(inst, "ldr", 3) || cmpstr(inst, "str", 3)){
            //First check if is a pop {pc}
            if(  (((opcode>>12) & 0xf) == 15) //if dest is pc
              && (((opcode>>16) & 0xf) == 13) //and source is sp
              && ((opcode & 0xf) == 4) //and the offset is #4
              && !((opcode>>24) & 0x1) ) //and is a post-indexed address (the address generated later replaces the base register)
            {
              *regs |= 1<<31;
              sprintf(inst, "pop {pc}");
              *instr_type = INS_RET;
            }
            else{
                reg1 = ((opcode>>12) & 0xf);
                reg2 = ((opcode>>16) & 0xf);
                *regs |= ( (1<<reg1) | ((1<<reg2) << 16) );
                *reg_shift = reg2; // In case it is a pre/post indexing //
                sprintf(instr_temp, " r%d, [r%d", reg1, reg2);
                strcat(inst, instr_temp);
                if(cmpstr(inst, "str", 3) && (opcode>>29 == 7)){ //without condition
                  *instr_type |= INS_STR;
                }

                if( (((opcode>>25) & 0x1) || (*(inst + 3) == 'd')) && (!((opcode>>22) & 0x1)) ){ //offset is a register or is a Doubleword instruction
                    reg3 = (opcode & 0xf);
                    *regs |= ((1<<reg3) << 16);
                    if(((opcode>>23) & 0x1)){   //add offset to base
                        if(opcode & 0x01000000){ // Pre indexing
                          sprintf(instr_temp, ", r%d]", reg3);
                        }
                        else{
                          sprintf(instr_temp, "], r%d", reg3);
                        }
                    }
                    else{   //substract offset from base
                        if(opcode & 0x01000000){
                          sprintf(instr_temp, ", -r%d]", reg3);
                        }
                        else{
                          sprintf(instr_temp, "], -r%d", reg3);
                        }
                    }
                    strcat(inst, instr_temp);
                }
                else{   //offset is an inmediate value
                    *use_inmediate = 1;
                    if( *(inst + 3) == 'd' ){ //if it is a Doubleword like ldrd or strd
                      *inmediate = ((opcode>>4) & 0xf0) | (opcode & 0xf);
                    }
                    else{
                      *inmediate = (opcode & 0xfff);
                    }

                    if( !((opcode>>23) & 0x1) ){ //substract offset from base
                      *inmediate *= -1;
                    }
                    if(opcode & 0x01000000){ // Pre indexing
                        if(*inmediate){
                          sprintf(instr_temp, ", #%d]", *inmediate);
                        }
                        else{
                          sprintf(instr_temp, "]");
                        }
                    }
                    else { // Post indexing
                        if(*inmediate){
                          sprintf(instr_temp, "], #%d", *inmediate);
                        }
                        else{
                          sprintf(instr_temp, "]");
                        }
                    }
                    strcat(inst, instr_temp);
                }
            }
        }
        else if(cmpstr(inst, "ldm", 3) || cmpstr(inst, "stm", 3)){
            // If value of Base register is 0xd -> r13 -> sp:
            // if is a load && bit W is '1' and bit S is '0' -> pop
            // if is a store && bit W is '1' and bit U is '0' -> push
            if(((opcode >> 16) & 0xf) == 0xd && cmpstr(inst, "ld", 2) && ((opcode>>21) & 0x1) && !((opcode>>22) & 0x1)){
              *operation = OP_POP;
              sprintf(inst, "%s%s ", "pop", condfield[(opcode>>28) & 0xf]);
            }
            else if(((opcode >> 16) & 0xf) == 0xd && cmpstr(inst, "st", 2) && ((opcode >> 21) & 0x1) && !((opcode>>23) & 0x1)){
              sprintf(inst, "%s%s ", "push", condfield[(opcode>>28) & 0xf]);
            }
            if(cmpstr(inst, "pus", 3) || cmpstr(inst, "pop", 3))
              sprintf(instr_temp, " {");
            else{
                if((opcode >> 21) & 0x1){ //If writeback
                  sprintf(instr_temp, " r%d!, {", ((opcode>>16) & 0xf));
                }
                else{
                  sprintf(instr_temp, " r%d, {", ((opcode>>16) & 0xf));
                }
            }
            strcat(inst, instr_temp);

            for(i = 0, j = 1; j <= 32768; i++, j<<=1) //2^15 = 32768
                if(opcode & j){
                    *regs |= (1<<(16+i));
                    sprintf(instr_temp, "r%d, ", i);
                    strcat(inst, instr_temp);
                    if( (i == 15) && cmpstr(inst, "pop", 3)){
                        *instr_type = INS_RET;
                    }
                }
            if((cmpstr(inst, "ldm", 3) || cmpstr(inst, "stm", 3)) && (opcode>>22) & 0x1) //If bit S
                sprintf(instr_temp, "\b\b}^");
            else
                sprintf(instr_temp, "\b\b}");
            strcat(inst, instr_temp);
        }
        if(((opcode>>21) & 0x1) && !( cmpstr(inst, "pus", 3)
           || cmpstr(inst, "pop", 3)
           || cmpstr(inst, "ldm", 3)
           || cmpstr(inst, "stm", 3) ))
                strcat(inst, "!");
        return;
    } ///end Load-Store

    return;
}

void setopcodetab(){
    int i, j;

    for(i = 0; i < 16; i++){
        opcodetab[i][0x00] = "and";
        opcodetab[i][0x01] = "ands";
    }
    opcodetab[0xb][0x01] = "ldrh";

    for(i = 0; i < 16; i++){
        opcodetab[i][0x02] = "eor";
        opcodetab[i][0x03] = "eors";
    }
    for(i = 0; i < 16; i++){
        opcodetab[i][0x04] = "sub";
        opcodetab[i][0x05] = "subs";
    }
    for(i = 0; i < 16; i++){
        opcodetab[i][0x06] = "rsb";
        opcodetab[i][0x07] = "rsbs";
    }
    for(i = 0; i < 16; i++){
        opcodetab[i][0x08] = "add";
        opcodetab[i][0x09] = "adds";
    }
    opcodetab[0xb][0x09] = "ldrh";

    for(i = 0; i < 16; i++){
        opcodetab[i][0x0a] = "adc";
        opcodetab[i][0x0b] = "adcs";
    }
    for(i = 0; i < 16; i++){
        opcodetab[i][0x0c] = "sbc";
        opcodetab[i][0x0d] = "sbcs";
    }
    opcodetab[0xb][0x0d] = "ldrh";

    for(i = 0; i < 16; i++){
        opcodetab[i][0x0e] = "rsc";
        opcodetab[i][0x0f] = "rscs";
    }

    opcodetab[0][0x10] = "mrs";
    opcodetab[5][0x10] = "qadd";
    opcodetab[8][0x10] = "smlabb";
    opcodetab[10][0x10] = "smlatb";
    opcodetab[12][0x10] = "smlabt";
    opcodetab[14][0x10] = "smlatt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x11] = "tst";
    opcodetab[0xb][0x11] = "ldrh";

    opcodetab[0][0x12] = "msr";
    opcodetab[1][0x12] = "bx";
    opcodetab[3][0x12] = "blx";
    opcodetab[5][0x12] = "qsub";
    opcodetab[7][0x12] = "bkpt";
    opcodetab[8][0x12] = "smlawb";
    opcodetab[10][0x12] = "smulwb";
    opcodetab[12][0x12] = "smlawt";
    opcodetab[14][0x12] = "smulwt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x13] = "teq";

    opcodetab[0][0x14] = "mrs";
    opcodetab[5][0x14] = "qdadd";
    opcodetab[8][0x14] = "smlalbb";
    opcodetab[10][0x14] = "smlaltb";
    opcodetab[12][0x14] = "smlalbt";
    opcodetab[14][0x14] = "smlaltt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x15] = "cmp";
    opcodetab[0xb][0x15] = "ldrh";

    opcodetab[0][0x16] = "msr";
    opcodetab[1][0x16] = "clz";
    opcodetab[5][0x16] = "qdsub";
    opcodetab[8][0x16] = "smulbb";
    opcodetab[10][0x16] = "smultb";
    opcodetab[12][0x16] = "smulbt";
    opcodetab[14][0x16] = "smultt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x17] = "cmn";

    for(i = 0; i < 16; i++){
        opcodetab[i][0x18] = "orr";
        opcodetab[i][0x19] = "orrs";
    }
    opcodetab[0xb][0x19] = "ldrh";

    for(i = 0; i < 16; i++){
        opcodetab[i][0x1a] = "mov";
        opcodetab[i][0x1b] = "movs";
    }
    for(i = 0; i < 16; i++){
        opcodetab[i][0x1c] = "bic";
        opcodetab[i][0x1d] = "bics";
    }
    opcodetab[0xb][0x1d] = "ldrh";
    opcodetab[0xf][0x1d] = "ldrsh";

    for(i = 0; i < 16; i++){
        opcodetab[i][0x1e] = "mvn";
        opcodetab[i][0x1f] = "mvns";
    }

    //Columna 9 e instr. invalidas
    opcodetab[9][0x00] = "mul";
    opcodetab[9][0x01] = "muls";
    opcodetab[9][0x02] = "mla";
    opcodetab[9][0x03] = "mlas";
    opcodetab[9][0x08] = "umull";
    opcodetab[9][0x09] = "umulls";
    opcodetab[9][0x0a] = "umlal";
    opcodetab[9][0x0b] = "umlals";
    opcodetab[9][0x0c] = "smull";
    opcodetab[9][0x0d] = "smulls";
    opcodetab[9][0x0e] = "smlal";
    opcodetab[9][0x0f] = "smlals";
    opcodetab[9][0x10] = "swp";
    opcodetab[9][0x14] = "swpb";

    opcodetab[9][0x04] = opcodetab[9][0x05] =
    opcodetab[9][0x06] = opcodetab[9][0x07] =
    opcodetab[1][0x10] = opcodetab[2][0x10] =
    opcodetab[3][0x10] = opcodetab[4][0x10] =
    opcodetab[6][0x10] = opcodetab[7][0x10] =
    opcodetab[9][0x11] = opcodetab[2][0x12] =
    opcodetab[4][0x12] = opcodetab[6][0x12] =
    opcodetab[9][0x12] = opcodetab[9][0x13] =
    opcodetab[1][0x14] = opcodetab[2][0x14] =
    opcodetab[3][0x14] = opcodetab[4][0x14] =
    opcodetab[6][0x14] = opcodetab[7][0x14] =
    opcodetab[9][0x15] = opcodetab[2][0x16] =
    opcodetab[3][0x16] = opcodetab[4][0x16] =
    opcodetab[6][0x16] = opcodetab[7][0x16] =
    opcodetab[9][0x16] = opcodetab[9][0x17] =
    opcodetab[9][0x18] = opcodetab[9][0x19] =
    opcodetab[9][0x1a] = opcodetab[9][0x1b] =
    opcodetab[9][0x1c] = opcodetab[9][0x1d] =
    opcodetab[9][0x1e] = opcodetab[9][0x1f] =
    "invalid instr";

    opcodetab[9][0x08] = "umull";
    opcodetab[9][0x09] = "umulls";
    opcodetab[9][0x0a] = "umlal";
    opcodetab[9][0x0b] = "umlals";
    opcodetab[9][0x0c] = "smull";
    opcodetab[9][0x0d] = "smulls";
    opcodetab[9][0x0e] = "smlal";
    opcodetab[9][0x0f] = "smlals";
    opcodetab[9][0x10] = "swp";

    //Columnas 11, 13, 15
    for(j = 0; j <= 0x1F; j++)
        if (j % 2 == 0) opcodetab[11][j] = "strh";
        else    opcodetab[11][j] = "ldrh";
    for(j = 0; j <= 0x1F; j++)
        if (j % 2 == 0) opcodetab[13][j] = "ldrd";
        else    opcodetab[13][j] = "ldrsb";
    for(j = 0; j <= 0x1F; j++)
        if (j % 2 == 0) opcodetab[15][j] = "strd";
        else    opcodetab[15][j] = "ldrsh";


    // 0x20
    for(i = 0; i < 16; i++)
        opcodetab[i][0x20] = "and";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x21] = "ands";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x22] = "eor";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x23] = "eors";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x24] = "sub";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x25] = "subs";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x26] = "rsb";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x27] = "rsbs";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x28] = "add";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x29] = "adds";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x2a] = "adc";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x2b] = "adcs";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x2c] = "sbc";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x2d] = "sbcs";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x2e] = "rsc";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x2f] = "rscs";

    for(i = 0; i < 16; i++)
        opcodetab[i][0x30] = opcodetab[i][0x34] = "invalid instr";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x31] = "tst";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x32] = "msr";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x33] = "teq";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x35] = "cmp";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x36] = "msr";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x37] = "cmn";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x38] = "orr";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x39] = "orrs";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x3a] = "mov";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x3b] = "movs";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x3c] = "bic";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x3d] = "bics";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x3e] = "mvn";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x3f] = "mvns";

    for(i = 0; i < 16; i++)
        opcodetab[i][0x40] = opcodetab[i][0x48] =
        opcodetab[i][0x50] =  opcodetab[i][0x52] =
        opcodetab[i][0x58] = opcodetab[i][0x5a] = "str";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x41] = opcodetab[i][0x49] =
        opcodetab[i][0x51] = opcodetab[i][0x53] =
        opcodetab[i][0x59] = opcodetab[i][0x5b] = "ldr";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x42] = opcodetab[i][0x4a] = "strt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x43] = opcodetab[i][0x4b] = "ldrt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x44] = opcodetab[i][0x4c] =
        opcodetab[i][0x54] = opcodetab[i][0x5e] = "strb";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x45] = opcodetab[i][0x4d] =
        opcodetab[i][0x55] = opcodetab[i][0x57] =
        opcodetab[i][0x5d] = opcodetab[i][0x5f] = "ldrb";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x46] = opcodetab[i][0x4e] = "strbt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x47] = opcodetab[i][0x4f] = "ldrbt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x56] = opcodetab[i][0x5c] = "strb";

    //0x60
    for(i = 0; i < 16; i++)
        opcodetab[i][0x60] = opcodetab[i][0x68] =
        opcodetab[i][0x70] = opcodetab[i][0x72] =
        opcodetab[i][0x78] = opcodetab[i][0x7a] = "str";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x61] = opcodetab[i][0x69] =
        opcodetab[i][0x71] = opcodetab[i][0x73] =
        opcodetab[i][0x79] = opcodetab[i][0x7b] = "ldr";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x62] = opcodetab[i][0x6a] = "strt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x63] = opcodetab[i][0x6b] = "ldrt";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x64] = opcodetab[i][0x6c] =
        opcodetab[i][0x74] = opcodetab[i][0x76] =
        opcodetab[i][0x7c] = opcodetab[i][0x7e] = "strb";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x65] = opcodetab[i][0x67] =
        opcodetab[i][0x6d] = opcodetab[i][0x6f] =
        opcodetab[i][0x75] = opcodetab[i][0x77] =
        opcodetab[i][0x7d] = opcodetab[i][0x7f] = "ldrb";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x66] = opcodetab[i][0x6e] = "strt";

    //Columnas 1, 3, 5, 7, 9, 11, 13, 15
    for(j = 0x60; j <= 0x7f; j++)
        for(i = 0; i < 16; i++)
            if (i % 2 != 0){
                opcodetab[1][j] = "invalid instr";
                opcodetab[3][j] = "invalid instr";
                opcodetab[5][j] = "invalid instr";
                opcodetab[7][j] = "invalid instr";
                opcodetab[9][j] = "invalid instr";
                opcodetab[11][j] = "invalid instr";
                opcodetab[13][j] = "invalid instr";
                opcodetab[15][j] = "invalid instr";
            }

    //0x80
    for(i = 0; i < 16; i++)
        opcodetab[i][0x80] = opcodetab[i][0x82] =
        opcodetab[i][0x84] = opcodetab[i][0x86] = "stmda";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x81] = opcodetab[i][0x83] =
        opcodetab[i][0x85] = opcodetab[i][0x87] = "ldmda";
    for(i = 0; i < 16; i++){
        opcodetab[i][0x8a] =
        opcodetab[i][0x8c] = opcodetab[i][0x8e] = "stmia";

        opcodetab[i][0x88] = "stm";
    }

    for(i = 0; i < 16; i++){
        opcodetab[i][0x89] =
        opcodetab[i][0x8b] =
        opcodetab[i][0x8d] =
        opcodetab[i][0x8f] = "ldm";
    }
    for(i = 0; i < 16; i++){
        opcodetab[i][0x90] =
        opcodetab[i][0x92] =
        opcodetab[i][0x94] =
        opcodetab[i][0x96] = "stmdb";
    }

    for(i = 0; i < 16; i++)
        opcodetab[i][0x91] = opcodetab[i][0x93] =
        opcodetab[i][0x95] = opcodetab[i][0x97] = "ldmdb";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x98] = opcodetab[i][0x9a] =
        opcodetab[i][0x9c] = opcodetab[i][0x9e] = "stmib";
    for(i = 0; i < 16; i++)
        opcodetab[i][0x99] = opcodetab[i][0x9b] =
        opcodetab[i][0x9d] = opcodetab[i][0x9f] = "ldmib";

    //0xA0
    for(j = 0xa0; j <= 0xaf; j++)
        for(i = 0; i < 16; i++)
            opcodetab[i][j] = "b";
    for(j = 0xb0; j <= 0xbf; j++)
        for(i = 0; i < 16; i++)
            opcodetab[i][j] = "bl";

    //0xC0
    for(i = 0; i < 16; i++)
        opcodetab[i][0xc0] = opcodetab[i][0xc2] =
        opcodetab[i][0xc4] = opcodetab[i][0xc6] =
        opcodetab[i][0xc8] = opcodetab[i][0xca] =
        opcodetab[i][0xcc] = opcodetab[i][0xce] =
        opcodetab[i][0xd0] = opcodetab[i][0xd2] =
        opcodetab[i][0xd4] = opcodetab[i][0xd6] =
        opcodetab[i][0xd8] = opcodetab[i][0xda] =
        opcodetab[i][0xdc] = opcodetab[i][0xde] = "stc";

    for(i = 0; i < 16; i++)
        opcodetab[i][0xc1] = opcodetab[i][0xc3] =
        opcodetab[i][0xc5] = opcodetab[i][0xc7] =
        opcodetab[i][0xc9] = opcodetab[i][0xcb] =
        opcodetab[i][0xcd] = opcodetab[i][0xcf] =
        opcodetab[i][0xd1] = opcodetab[i][0xd3] =
        opcodetab[i][0xd5] = opcodetab[i][0xd7] =
        opcodetab[i][0xd9] = opcodetab[i][0xdb] =
        opcodetab[i][0xdd] = opcodetab[i][0xdf] = "ldc";

    //0xE0
    for(i = 0; i < 16; i++)
        for(j = 0xe0; j <= 0xef; j++)
            if( i % 2 == 0 ) opcodetab[i][j] = "cdp";
            else{
                if( j % 2 == 0 ) opcodetab[i][j] = "mcr";
                else opcodetab[i][j] = "mrc";
            }
    //0xF0
    for(j = 0xf0; j <= 0xff; j++)
        for(i = 0; i < 16; i++)
            opcodetab[i][j] = "svc";
}
