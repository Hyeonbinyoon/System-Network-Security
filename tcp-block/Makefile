CXX = g++
CXXFLAGS = -Wall -O2 -std=c++17
LDLIBS = -lpcap

TARGET = tcp-block
OBJS = main.o packet.o checksum.o http_parser.o hb_headers.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

main.o: main.cpp packet.h hb_headers.h
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

packet.o: packet.cpp packet.h checksum.h http_parser.h hb_headers.h
	$(CXX) $(CXXFLAGS) -c packet.cpp -o packet.o

checksum.o: checksum.cpp checksum.h hb_headers.h
	$(CXX) $(CXXFLAGS) -c checksum.cpp -o checksum.o

http_parser.o: http_parser.cpp http_parser.h
	$(CXX) $(CXXFLAGS) -c http_parser.cpp -o http_parser.o

hb_headers.o: hb_headers.cpp hb_headers.h
	$(CXX) $(CXXFLAGS) -c hb_headers.cpp -o hb_headers.o

clean:
	rm -f $(OBJS) $(TARGET)

