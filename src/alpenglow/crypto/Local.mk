ifdef FD_HAS_BLST
$(call add-hdrs,ag_aggsig.h)
$(call add-objs,ag_aggsig,ag_alpenglow)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_aggsig,test_aggsig,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_aggsig)
endif
endif
