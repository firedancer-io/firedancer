ifneq (,$(wildcard $(OPT)/lib/libflatccrt.a))
FLATCC_LIBS:=$(OPT)/lib/libflatccrt.a
else
$(info "flatcc not installed, skipping")
endif
