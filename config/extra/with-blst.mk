ifneq (,$(wildcard $(OPT)/lib/libblst.a))
FD_HAS_BLST:=1
CFLAGS+=-DFD_HAS_BLST=1
BLST_LIBS:=$(OPT)/lib/libblst.a
LDFLAGS+=$(BLST_LIBS)
else
$(warning "blst not installed, skipping")
endif
