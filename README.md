## Synopsis
*Frop* is a Return Oriented Programming (ROP) gadget finder for ELF files of the ARM architecture. It is a degree final project, but please, don't hesitate in notify of any bug.

## Installation                                                                         
*Frop* doesn’t require any install, only compile with the ‘make’ command and execute it.

## Example
	Usage: frop [OPTION...] file
	Toolchain for ROP explotation (ELF binaries & ARM architecture)
	
	  -a, --all                  Show gadgets and build the payload for '/bin/sh'
	  -c, --chain                Build the payload for '/bin/sh'
	  -g, --gadgets              Show useful gadgets.
	  -l --length                Set max number of instructions of each gadget
	                             (only with -g)
	  -?, --help                 Give this help list
	      --usage                Give a short usage message
	  -V, --version              Print program version
	
	Report bugs to <fernando () fervagar.com >

