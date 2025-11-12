$(call add-objs,fd_reasm,fd_discof)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_reasm,test_reasm,fd_discof fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_reasm)
endif
