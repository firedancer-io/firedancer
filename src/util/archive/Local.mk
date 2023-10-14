$(call add-hdrs,fd_ar.h fd_tar.h)
$(call add-objs,fd_ar fd_tar,fd_util)
$(call make-unit-test,test_ar,test_ar,fd_util)
$(call run-unit-test,test_ar,)
$(call fuzz-test,fuzz_tar,fuzz_tar,fd_ballet fd_util)

