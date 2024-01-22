$(call add-hdrs,fd_hex.h)
$(call add-objs,fd_hex,fd_ballet)
$(call fuzz-test,fuzz_hex,fuzz_hex,fd_ballet fd_util)
