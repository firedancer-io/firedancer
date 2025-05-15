ifneq (,$(wildcard $(OPT)/lib/libblst.a))
FD_HAS_BLST:=1
CFLAGS+=-DFD_HAS_BLST=1
LDFLAGS+=$(OPT)/lib/libblst.a
else
$(warning "blst not installed, skipping")
endif
