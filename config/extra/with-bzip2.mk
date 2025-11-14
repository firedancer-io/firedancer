ifeq ($(wildcard $(OPT)/git/bzip2/bzlib.c),)
$(warning "bzip2 not installed, skipping")
else

FD_HAS_BZIP2:=1
CFLAGS+=-DFD_HAS_BZIP2=1

endif
