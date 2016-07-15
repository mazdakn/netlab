CC = gcc
CFLAGS  = -g -Wall
INCLUDES = -I'../lib/'
LIBS = -lpcap

SRCS = $(wildcard *.c protocols/*.c ../lib/*.c)
OBJS = $(SRCS:.c=.o)
MONITOR = monitor

all: $(MONITOR)

$(MONITOR): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MONITOR) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c  $<  -o $@

clean:
	$(RM) *.o *~ $(MONITOR) protocols/*.o 

depend: $(SRCS)
	makedepend $(INCLUDES) $^

