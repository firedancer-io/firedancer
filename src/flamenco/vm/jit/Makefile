# Run 'make vendor' to refresh dynasm headers from the latest LuaJIT checkout.

LUA ?= lua-5.1

.PHONY: generate
generate: fd_vm_jitproto.c

fd_vm_jitproto.c: fd_vm_jitproto.dasc
	$(LUA) ../../../../opt/git/luajit/dynasm/dynasm.lua -o $@ $<

.PHONY: vendor
vendor:
	rm -v dasm_{proto,x86}.h
	cp ../../../../opt/git/luajit/dynasm/dasm_{proto,x86}.h .
