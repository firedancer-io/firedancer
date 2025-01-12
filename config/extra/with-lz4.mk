ifneq (,$(wildcard $(OPT)/lib/liblz4.a))
FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
LDFLAGS+=$(OPT)/lib/liblz4.a
else
$(info "lz4 not installed, skipping")
endif
