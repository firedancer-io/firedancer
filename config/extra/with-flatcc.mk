ifneq (,$(wildcard $(OPT)/lib/libflatccrt.a))
FLATCC_LIBS:=$(OPT)/lib/libflatccrt.a
FD_HAS_FLATCC:=1
CPPFLAGS+=-DFD_HAS_FLATCC=1
else
$(info "flatcc not installed, skipping")
endif
