CC=g++

CFLAGS=-Wall

all:
	$(CC) $(CFLAGS) src/aes.cpp -o build/prog
debug:
	$(CC) $(CFLAGS) -g src/aes.cpp -o build/debug
test:
	$(CC) $(CFLAGS) tests/test.cpp -lgtest -lgtest_main -pthread -o build/test	
clean:
	rm -rf build/*.o build/prog build/test
