CFLAGS:=-Wall -O2 -ggdb

all: frop

frop: linkedlist.c disass.c disassfuncs.c chain.c p_sh.c print_py.c frop.c
