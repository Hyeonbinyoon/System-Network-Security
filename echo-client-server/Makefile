CXX = g++
CXXFLAGS = -Wall -O2 -pthread

TARGETS = echo-client echo-server
OBJS = echo-client.o echo-server.o

all: $(TARGETS)

echo-client: echo-client.o
	$(CXX) $(CXXFLAGS) echo-client.o -o echo-client

echo-server: echo-server.o
	$(CXX) $(CXXFLAGS) echo-server.o -o echo-server

echo-client.o: echo-client.cpp
	$(CXX) $(CXXFLAGS) -c echo-client.cpp -o echo-client.o

echo-server.o: echo-server.cpp
	$(CXX) $(CXXFLAGS) -c echo-server.cpp -o echo-server.o

clean:
	rm -f $(TARGETS) $(OBJS)