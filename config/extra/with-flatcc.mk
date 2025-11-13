ifneq (,$(wildcard $(OPT)/lib/libflatcc.a))
FLATCC_LIBS:=$(OPT)/lib/libflatcc.a $(OPT)/lib/libflatccrt.a
else
$(info "flatcc not installed, skipping")
endif
