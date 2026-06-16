$(call add-hdrs,fd_eqvoc.h)
$(call add-objs,fd_eqvoc,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_eqvoc,test_eqvoc,fd_choreo fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_eqvoc)
$(call make-unit-test,test_eqvoc_last_shred_poc,test_eqvoc_last_shred_poc,fd_choreo fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_eqvoc_last_shred_poc)
$(call make-fuzz-test,fuzz_eqvoc,fuzz_eqvoc,fd_choreo fd_flamenco fd_ballet fd_util)
endif
