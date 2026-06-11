CC = gcc

TARGET = send-arp

SRCS = main.c hb_headers.c arp_utils.c
OBJS = $(SRCS:.c=.o)

CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
