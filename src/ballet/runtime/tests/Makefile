PYTHON?=python3

.PHONY: all
all: test_native_programs.c

test_native_programs.c: gen_c_tests.py system_program_tests.json
	$(PYTHON) gen_c_tests.py -j system_program_tests.json

.PHONY: clean
clean:
	rm -rf test_native_programs.c generated/
