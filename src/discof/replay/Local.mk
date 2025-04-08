ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_replay_tile fd_replay_thread,fd_replay)
endif
endif
