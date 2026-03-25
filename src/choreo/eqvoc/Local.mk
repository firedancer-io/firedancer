ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_eqvoc.h)
$(call add-objs,fd_eqvoc,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_eqvoc,test_eqvoc,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_eqvoc,fuzz_eqvoc,fd_choreo fd_flamenco fd_ballet fd_util)
endif
endif
