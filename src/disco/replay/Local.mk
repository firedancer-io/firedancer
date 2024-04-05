$(call add-hdrs,fd_replay.h)
$(call add-objs,fd_replay,fd_disco)
$(call make-unit-test,test_replay,test_replay,fd_disco fd_tango fd_util)
$(call make-bin,fd_replay_tile,fd_replay_tile,fd_disco fd_tango fd_util)
