ifdef FD_HAS_INT128
$(call add-hdrs,fd_voter.h)
$(call add-objs,fd_voter,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-bin,fd_voter_ctl,fd_voter_ctl,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_voter,test_voter,fd_choreo fd_flamenco fd_ballet fd_util)
endif
endif
