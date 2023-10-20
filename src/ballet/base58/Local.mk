$(call add-hdrs,fd_base58.h)
$(call add-objs,fd_base58,fd_ballet)
$(call make-unit-test,test_base58,test_base58,fd_ballet fd_util)
$(call fuzz-test,fuzz_base58,fuzz_base58,fd_ballet fd_util)
