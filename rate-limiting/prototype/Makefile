CC = gcc
CFLAGS  = -g -Wall
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
TARGET = case_client

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c  $<  -o $@

clean:
	$(RM) *.o *~ $(TARGET)


