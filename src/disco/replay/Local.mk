ifdef FD_HAS_INT128
$(call add-hdrs,fd_replay.h)
$(call add-objs,fd_replay,fd_disco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_replay,test_replay,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
endif
endif
