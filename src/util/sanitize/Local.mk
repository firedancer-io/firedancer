$(call add-hdrs,fd_asan.h fd_msan.h fd_sanitize.h)
$(call make-lib,fd_fuzz_stub)
$(call add-objs,fd_fuzz_stub,fd_fuzz_stub)
$(call make-lib,fd_hfuzz_stubs)
$(call add-objs,fd_hfuzz_metrics_stubs,fd_hfuzz_stubs)

ifdef FD_HAS_DEEPASAN_WATCH
CPPFLAGS+=-DFD_HAS_DEEPASAN_WATCH=1
$(call add-objs,fd_asan fd_backtrace,fd_util)
endif
