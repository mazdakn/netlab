CC = gcc
CFLAGS  = -g -Wall
INCLUDES = 
LIBS =

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

all: $(OBJS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c  $<  -o $@

clean:
	$(RM) *.o

depend: $(SRCS)
	makedepend $(INCLUDES) $^

