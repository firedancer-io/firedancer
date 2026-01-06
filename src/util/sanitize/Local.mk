$(call add-hdrs,fd_asan.h fd_msan.h fd_tsa.h fd_sanitize.h)
$(call make-lib,fd_fuzz_stub)
$(call add-objs,fd_fuzz_stub,fd_fuzz_stub)

ifdef FD_HAS_DEEPASAN_WATCH
CPPFLAGS+=-DFD_HAS_DEEPASAN_WATCH=1
$(call add-objs,fd_asan fd_backtrace,fd_util)
endif
