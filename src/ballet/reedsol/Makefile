ZIG ?= zig
CPU ?= x86_64_v4

SRCS :=
SRCS += fd_reedsol_gfni_32

OUTPUTS:=$(SRCS:=.S)

.PHONY: generate clean

generate: $(OUTPUTS)

%.S: %.zig
	$(ZIG) build-obj $< -target x86_64-linux -mcpu=icelake_server -fno-emit-bin -OReleaseFast -fstrip -femit-asm=$@ -fPIE

clean:
	rm -f $(OUTPUTS)
