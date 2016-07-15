CC = gcc
CFLAGS  = -g -Wall
INCLUDES = -I'../lib/'
LIBS =

SRCS = $(wildcard *.c ../lib/*.c)
OBJS = $(SRCS:.c=.o)
TARGET = netproxy

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c  $<  -o $@

clean:
	$(RM) *.o *~ $(TARGET)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

