$(call add-hdrs,fd_hex.h)
$(call add-objs,fd_hex,fd_ballet)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_hex,fuzz_hex,fd_ballet fd_util)
endif
