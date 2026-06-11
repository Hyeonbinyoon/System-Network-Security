CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic
LDFLAGS = -lpcap -pthread

TARGET = tls-block

SRCS = \
	main.cpp \
	checksum.cpp \
	flow.cpp \
	hb_headers.cpp \
	packet_parser.cpp \
	rst_sender.cpp \
	tls_record_reassembly.cpp \
	tls_handshake_reassembly.cpp \
	tls_client_hello_parser.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

