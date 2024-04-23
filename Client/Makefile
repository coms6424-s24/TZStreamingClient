CC=g++

client.o: client.cpp client.h
	$(CC) -c client.cpp

main_test.o: main_test.cpp client.h
	$(CC) -c main_test.cpp

host: client.o main_test.o
	$(CC) -o test client.o main_test.o