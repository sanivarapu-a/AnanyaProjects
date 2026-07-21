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

echo: echo.o
	$(LD)   -o $@ $^  $(LDFLAGS)

echo.o: echo.c my_libc.h

.PHONY: clean
clean:
	rm -f -- *.o echo a.out

.PHONY: all
all: clean echo
