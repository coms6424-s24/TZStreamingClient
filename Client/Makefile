CC=g++
CFLAGS=-I.
DEPS = client.h
OBJ = client.o main_test.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)