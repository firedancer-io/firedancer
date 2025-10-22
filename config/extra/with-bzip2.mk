ifneq (,$(wildcard $(OPT)/lib/libbz2.a))
FD_HAS_BZIP2:=1
CFLAGS+=-DFD_HAS_BZIP2=1
LDFLAGS+=$(OPT)/lib/libbz2.a
else
$(warning "bzip2 not installed, skipping")
endif
