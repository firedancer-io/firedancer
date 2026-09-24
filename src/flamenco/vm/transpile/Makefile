LUAJIT ?= luajit
DYNASM ?= ../../../third_party/luajit/dynasm/dynasm.lua

.PHONY: all generate clean

all: generate

generate: fd_transpile_x86.c

%.c: %.dasc
	$(LUAJIT) $(DYNASM) -o $@ $<

clean:
	rm -f fd_transpile_x86.c
