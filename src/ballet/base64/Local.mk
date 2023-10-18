$(call add-hdrs,fd_base64.h)
$(call add-objs,fd_base64,fd_ballet)
$(call make-unit-test,test_base64,test_base64,fd_ballet fd_util)
$(call fuzz-test,fuzz_base64,fuzz_base64,fd_ballet fd_util)
