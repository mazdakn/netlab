CC = gcc
CFLAGS  = -g -Wall
INCLUDES = -I'../lib/'

SRCS = $(wildcard *.c ../lib/*.c)
OBJS = $(SRCS:.c=.o)
GENERATOR = generator

all: $(GENERATOR)

$(GENERATOR): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(GENERATOR) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c  $<  -o $@

clean:
	$(RM) *.o *~ $(GENERATOR) protocols/*.o 

depend: $(SRCS)
	makedepend $(INCLUDES) $^

