CC = g++
CFLAGS  = -g -Wall
INCLUDES = -I/usr/include/mysql++ -I/usr/include/mysql
LIBS = -lldns -lmysqlpp -lmysqlclient
SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)
TARGET = dnsperf

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(OBJS)  $(LIBS)

.cpp.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c  $<  -o $@

clean:
	$(RM) *.o *~ $(TARGET)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

