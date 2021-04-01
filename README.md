## NOTICE
This was a Bachelor's Degree Final Project that helped me to learn many aspects, such as ROP
programming basics and how to document the project itself. Unfortunately, I no longer maintain it.
It may contain bugs and has limited functionality. For example, return instructions different than
`pop pc` are not supported.

If you are seeking a tool like this to search for ROP gadgets,
I highly recommend you to take a look at [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) and [Ropper](https://github.com/sashs/Ropper).


## Synopsis

*Frop* is a Return Oriented Programming (ROP) gadget finder for ELF files of the ARM architecture. 

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

