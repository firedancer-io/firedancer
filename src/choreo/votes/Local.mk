$(call add-hdrs,fd_votes.h)
$(call add-objs,fd_votes,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_votes,test_votes,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_votes)
endif
