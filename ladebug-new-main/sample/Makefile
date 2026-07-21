CC=gcc
CFLAGS=-g -Wall -O0 -fno-omit-frame-pointer -fno-stack-protector
LDFLAGS=-no-pie

TARGETS = sum sum-pause sum-fpe
OBJECTS = sum.o sum-pause.o sum-fpe.o

.PHONY: default
default: $(TARGETS)

$(TARGETS):

$(OBJECTS):

.PHONY: clean
clean:
	rm -f *.o $(TARGETS)

.PHONY: all
all: clean default
