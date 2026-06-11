all: sum-nbo

sum-nbo: main.o load_numbers.o
	g++ -o sum-nbo main.o load_numbers.o

main.o: main.cpp load_numbers.h
	g++ -g -c -o main.o main.cpp

load_numbers.o: load_numbers.cpp load_numbers.h
	g++ -g -c -o load_numbers.o load_numbers.cpp

clean:
	rm -f sum-nbo
	rm -f *.o
