CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap

TARGET = arp-spoof
SRCS = main.c arp_utils.c hb_headers.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c hb_headers.h arp_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
