AS=as
LD=ld

ASFLAGS=
LDFLAGS=

hello: hello.o
	$(LD)   -o hello hello.o  $(LDFLAGS)

hello.o: hello.s

.PHONY: clean
clean:
	rm -f -- *.o hello a.out

.PHONY: all
all: clean hello
