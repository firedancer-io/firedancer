$(call add-hdrs,fd_notar.h)
$(call add-objs,fd_notar,fd_choreo)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_notar,test_notar,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_notar)
endif
endif
