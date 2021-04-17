CC=g++

CFLAGS=-Wall

all:
	$(CC) $(CFLAGS) src/aes.cpp -o build/prog
debug:
	$(CC) $(CFLAGS) -g src/aes.cpp -o build/debug
run:
	$(CC) $(CFLAGS) src/run.cpp -o build/run
test:
	$(CC) $(CFLAGS) tests/test.cpp -lgtest -lgtest_main -pthread -o build/test
# profile:
# bash -c "valgrind --tool=callgrind ./build/run"
# then run with qcachegrind on mac
coverage:
	$(CC) $(CFLAGS) tests/test.cpp -lgtest -lgtest_main -pthread -fprofile-arcs -ftest-coverage -o build/coverage
	bash -c "./build/coverage"
	bash -c "gcov test.gcno"
	bash -c "lcov --capture --directory . --output-file main_coverage.info"
	bash -c "genhtml main_coverage.info --output-directory cov"
clean_cov:
	rm *.gcov
clean:
	rm -rf build/*.o build/prog build/test
