ifdef FD_HAS_INT128
$(call add-hdrs,fd_zktpp.h)
$(call add-objs,fd_zktpp,fd_flamenco)
$(call make-unit-test,test_zktpp,test_zktpp,fd_flamenco fd_ballet fd_util)
endif
