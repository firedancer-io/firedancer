ifdef FD_HAS_INT128
$(call add-hdrs,fd_forks.h)
$(call add-objs,fd_forks,fd_choreo)
$(call make-unit-test,test_forks,test_forks,fd_choreo fd_flamenco fd_ballet fd_util)
endif
