CC=g++

CFLAGS=-Wall

all:
	$(CC) $(CFLAGS) src/aes.cpp -o build/prog
debug:
	$(CC) $(CFLAGS) -g src/aes.cpp -o build/debug
test:
	$(CC) $(CFLAGS) tests/test.cpp -lgtest -lgtest_main -pthread -o build/test
coverage:
	$(CC) $(CFLAGS) tests/test.cpp -lgtest -lgtest_main -pthread -fprofile-arcs -ftest-coverage -o build/coverage
clean:
	rm -rf build/*.o build/prog build/test
