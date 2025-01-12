ifneq (,$(wildcard $(OPT)/lib/libzstd.a))
FD_HAS_ZSTD:=1
CFLAGS+=-DFD_HAS_ZSTD=1
LDFLAGS+=$(OPT)/lib/libzstd.a
else
$(warning "zstd not installed, skipping")
endif
