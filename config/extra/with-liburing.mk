ifneq (,$(wildcard $(OPT)/lib/liburing.a))
FD_HAS_LIBURING:=1
CFLAGS+=-DFD_HAS_LIBURING=1
LDFLAGS+=$(OPT)/lib/liburing.a
else
$(warning "liburing not installed, skipping")
endif
