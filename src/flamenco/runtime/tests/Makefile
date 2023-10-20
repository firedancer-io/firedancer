PYTHON?=python3.8

.PHONY: all
all: test_native_programs.c

.PHONY: test_native_programs.c
test_native_programs.c: gen_c_tests.py
	$(PYTHON) gen_c_tests.py -j ../../../../../firedancer-testbins

.PHONY: clean
clean:
	rm -rf test_native_programs.c generated/
