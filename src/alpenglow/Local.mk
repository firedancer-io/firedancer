$(call make-lib,ag_alpenglow)
$(call add-hdrs,ag_alpenglow_base.h)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_alpenglow_base,test_alpenglow_base,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_alpenglow_base)
endif
