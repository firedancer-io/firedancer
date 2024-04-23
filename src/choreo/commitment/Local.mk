ifdef FD_HAS_INT128
$(call add-hdrs,fd_commitment.h)
$(call add-objs,fd_commitment,fd_choreo)
$(call make-unit-test,test_commitment,test_commitment,fd_choreo fd_flamenco fd_ballet fd_util)
endif
