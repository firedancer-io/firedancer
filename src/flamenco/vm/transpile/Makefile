PYTHON ?= python3

.PHONY: all generate test clean

all: generate

generate: fd_transpile_x86.c fd_transpile_arm64.c

%.c: %.dasc dasm/*.py
	$(PYTHON) dasm/fd_dasm.py -o $@ $<

test:
	$(PYTHON) dasm/test_fd_dasm.py

clean:
	rm -f fd_transpile_x86.c fd_transpile_arm64.c
