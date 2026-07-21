CC=gcc
LD=ld

# * -nostdlib: Do not use the standard system startup files or libraries when
#   linking. This switch also implies -nostartfiles. This lets us provide our
#   own _start function.
#
# * -fno-asynchronous-unwind-tables: Do not generate unwind information for
#   exception handling. This removes the .eh_frame section, which is not
#   necessary for our purposes.
#
# * -fcf-protection=none: Disable control flow protection. This removes the
#   .note.gnu.property sections, which are not necessary for our purposes.
#
CFLAGS=-Wall -nostdlib -fno-asynchronous-unwind-tables -fcf-protection=none
LDFLAGS=

main: my_libc.o main.o sum.o my_strlen.o print_ulong.o
	$(LD)   -o $@ $^  $(LDFLAGS)

my_libc.o: my_libc.c my_libc.h

main.o: main.c my_libc.h

sum.o: sum.c

my_strlen.o: my_strlen.c

print_ulong.o: print_ulong.c my_libc.h

.PHONY: clean
clean:
	rm -f -- *.o main a.out

.PHONY: all
all: clean main
