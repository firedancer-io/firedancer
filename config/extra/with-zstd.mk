ifneq (,$(wildcard opt/lib/libzstd.a))
FD_HAS_ZSTD:=1
CFLAGS+=-DFD_HAS_ZSTD=1
LDFLAGS+=opt/lib/libzstd.a
else
$(warning "zstd not installed, skipping")
endif
