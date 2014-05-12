
all: trapp_test

clean:
	rm -rf trapp_test

trapp_test: trapp_test.c
	$(CC) -o $@ $(CFLAGS) -O2 $<

run_verifier: trapp_test
	./trapp_test c

run_prover: trapp_test
	./trapp_test t
