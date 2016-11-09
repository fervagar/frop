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

#include <argp.h>
#include <stdlib.h>
#include "datatypes.h"
#include "disass.h"

int disass(int mode, char *filename);

// Arguments Parser //
const char *argp_program_version = "Frop v1.0";
const char *argp_program_bug_address = "<fernando@fervagar.com>";
static char doc[] = "Toolchain for ROP explotation (ELF binaries & ARM architecture)";
static char args_doc[] = "file";
static struct argp_option options[] = {
    { "all", 'a', 0, 0, "Show gadgets and build the payload for '/bin/sh'"},
    //{ "search", 's', 0, 0, "Search instructions in the binary file"},
    { "gadgets", 'g', 0, 0, "Show useful gadgets."},
    { 0, 'l', "--length", 0, "Set max number of instructions of each gadget (only with -g)"},
    { "chain", 'c', 0, 0, "Build the payload for '/bin/sh'"},
    { 0 }
};

struct arguments {
    program_mode_t mode;
    char *file;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
    case 'c': arguments->mode = CHAIN_MODE; break;
    case 'g': arguments->mode = GADGETS_MODE; break;
    //case 's': arguments->mode = SEARCH_MODE; break;
    case 'a': arguments->mode = ALL_MODE; break;
    case 'l': gadget_length = atoi(arg); break;
    case ARGP_KEY_ARG:
      if (state->arg_num >= 1){
        argp_usage(state);
      }
      else{
        arguments->file = arg;
      }
      break;
    case ARGP_KEY_END:
      if (state->arg_num < 1){
	       argp_usage (state);
	     }
      break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

int main(int argc, char **argv){
  struct arguments args;

  args.mode = ALL_MODE; //default mode: show gadgets + build chain
  gadget_length = 3; //default length: 3 instructions / gadget
  argp_parse(&argp, argc, argv, 0, 0, &args);

  if(gadget_length <= 0) gadget_length = 3;
  return disass(args.mode, args.file);
}
