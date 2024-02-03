$(call add-hdrs,fd_asan.h fd_msan.h fd_sanitize.h)
$(call make-lib,fd_fuzz_stub)
$(call add-objs,fd_fuzz_stub,fd_fuzz_stub)
