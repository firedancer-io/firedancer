ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_replay_tile fd_replay_thread fd_replay,fd_discof)
$(call make-unit-test,test_replay,test_replay,fd_discof fd_disco fd_flamenco fd_tango fd_util)
endif
endif
