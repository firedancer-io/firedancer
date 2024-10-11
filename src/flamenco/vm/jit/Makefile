# Run 'make vendor' to refresh dynasm headers from the latest LuaJIT checkout.

LUA ?= lua-5.1
LUAJIT ?= ../../../../opt/git/luajit

.PHONY: generate
generate: fd_jit_compiler.c

fd_jit_compiler.c: fd_jit_compiler.dasc
	$(LUA) $(LUAJIT)/dynasm/dynasm.lua -o $@ $<

.PHONY: vendor
vendor:
	rm -v dasm_{proto,x86}.h
	cp $(LUAJIT)/dynasm/dasm_{proto,x86}.h .
