# Makefile

CC=gcc
CFLAGS=
OBJS= main.o function.o
LIBS=
all :	add

add:	$(OBJS)
	$(CC) $(CFLAGS) -o pkcapture.out $(OBJS) $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -l stdhdr.h
function.o: function.c
	$(CC) $(CFLAGS) -c function.c -l stdhdr.h



clean:
	rm -f $(OBJS) pkcapture.out core
