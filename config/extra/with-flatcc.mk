ifneq (,$(wildcard $(OPT)/lib/libflatcc.a))
FD_HAS_FLATCC:=1
FLATCC_LIBS:=$(OPT)/lib/libflatcc.a $(OPT)/lib/libflatccrt.a
else
$(info "flatcc not installed, skipping")
endif
