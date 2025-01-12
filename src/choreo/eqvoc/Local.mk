ifdef FD_HAS_INT128
$(call add-hdrs,fd_eqvoc.h)
$(call add-objs,fd_eqvoc,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_eqvoc,test_eqvoc,fd_choreo fd_flamenco fd_ballet fd_util)
endif
endif
