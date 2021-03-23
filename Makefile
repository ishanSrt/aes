CC=g++

CFLAGS=-Wall

all:
	$(CC) $(CFLAGS) src/aes.cpp -o build/prog
test:
	$(CC) $(CFLAGS) tests/test.cpp -lgtest -lgtest_main -pthread -o build/test	
clean:
	rm -rf build/*.o build/prog build/test
