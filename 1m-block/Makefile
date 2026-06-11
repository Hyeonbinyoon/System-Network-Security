CXX=g++
CXXFLAGS=-std=c++17 -Wall -Wextra -O2
LDLIBS=-lnetfilter_queue

TARGET=1m-block
OBJS=1m-block.o hb_headers.o http_parser.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDLIBS)

1m-block.o: 1m-block.cpp hb_headers.h http_parser.h
	$(CXX) $(CXXFLAGS) -c 1m-block.cpp

hb_headers.o: hb_headers.cpp hb_headers.h
	$(CXX) $(CXXFLAGS) -c hb_headers.cpp

http_parser.o: http_parser.cpp http_parser.h
	$(CXX) $(CXXFLAGS) -c http_parser.cpp

clean:
	rm -f $(TARGET) $(OBJS)
