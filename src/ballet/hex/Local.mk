$(call add-hdrs,fd_hex.h)
$(call add-objs,fd_hex,fd_ballet)
$(call make-unit-test,test_hex,test_hex,fd_hex fd_ballet fd_util)
$(call run-unit-test,test_hex)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_hex,fuzz_hex,fd_ballet fd_util)
endif
