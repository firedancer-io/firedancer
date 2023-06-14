PYTHON?=python3.8

.PHONY: all
all: test_native_programs.c

test_native_programs.c: gen_c_tests.py tests/*.json
	$(PYTHON) gen_c_tests.py -j tests

.PHONY: clean
clean:
	rm -rf test_native_programs.c generated/
