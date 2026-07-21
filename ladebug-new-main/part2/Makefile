CC = gcc
CFLAGS = -g -Wall

OBJECTS = ldb.o ldb-step.o ldb-info.o

ldb: $(OBJECTS)

$(OBJECTS): ldb.h

.PHONY: clean
clean:
	rm -f *.o ldb
