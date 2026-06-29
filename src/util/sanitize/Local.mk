$(call add-hdrs,fd_asan.h fd_msan.h fd_tsa.h fd_sanitize.h)
ifdef FD_HAS_HOSTED
$(call make-lib,fd_fuzz_stub)
$(call add-objs,fd_fuzz_stub,fd_fuzz_stub)
$(call add-objs,fd_hfuzz_metrics_stubs,fd_util)
endif
