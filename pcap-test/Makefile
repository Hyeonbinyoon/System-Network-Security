CC = gcc
TARGET = pcap-test

SRCS = main.c parse.c
OBJS = $(SRCS:.c=.o)

CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

main.o: main.c hb-headers.h parse.h
	$(CC) $(CFLAGS) -c main.c

parse.o: parse.c hb-headers.h parse.h
	$(CC) $(CFLAGS) -c parse.c

clean:
	rm -f $(OBJS) $(TARGET)
