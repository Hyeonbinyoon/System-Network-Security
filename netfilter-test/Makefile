CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lnetfilter_queue

TARGET = netfilter-test
SRCS = netfilter_test.c

all: $(TARGET)

$(TARGET): $(SRCS) hb_headers.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
