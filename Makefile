# Makefile

CC=gcc
CFLAGS=
OBJS= main.o
LIBS=
all :	add

add:	$(OBJS)
	$(CC) $(CFLAGS) -o pkCapture.out $(OBJS) $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c



clean:
	rm -f $(OBJS) pkCapture.out core
