ifneq (,$(wildcard /usr/include/lz4.h)) # FIXME: DEPS.SH INSTALL
FD_HAS_LZ4:=1
CFLAGS+=-DFD_HAS_LZ4=1
LDFLAGS+=-llz4
else
$(warning "lz4 not installed, skipping")
endif
