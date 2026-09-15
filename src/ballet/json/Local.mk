$(call add-hdrs,fd_jtok.h)
$(call add-objs,fd_jtok,fd_ballet)
$(call make-unit-test,test_jtok,test_jtok,fd_ballet fd_util)
$(call run-unit-test,test_jtok)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_jtok,fuzz_jtok,fd_ballet fd_util)
endif
