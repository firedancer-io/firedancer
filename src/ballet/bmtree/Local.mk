$(call add-hdrs,fd_bmtree.h fd_wbmtree.h)
$(call add-objs,fd_bmtree fd_wbmtree,fd_ballet)

ifdef FD_HAS_ALLOCA
$(call make-unit-test,test_bmtree,test_bmtree,fd_ballet fd_util)
$(call run-unit-test,test_bmtree)
$(call fuzz-test,fuzz_bmtree,fuzz_bmtree,fd_ballet fd_util)
endif
