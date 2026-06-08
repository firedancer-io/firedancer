$(call add-hdrs,fd_aggsig.h)
$(call add-objs,fd_aggsig,fd_alpenglow)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_aggsig,test_aggsig,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_aggsig)
endif
