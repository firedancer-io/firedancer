$(call add-objs,fd_reasm,fd_discof)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_reasm,test_reasm,fd_discof fd_disco fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_reasm)
$(call make-fuzz-test,fuzz_reasm,fuzz_reasm,fd_discof fd_disco fd_ballet fd_util)
endif
