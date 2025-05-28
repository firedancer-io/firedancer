ifdef FD_HAS_INT128
$(call add-hdrs,fd_replay.h fd_replay_notif.h)
$(call add-objs,fd_replay,fd_discof)
$(call add-objs,fd_epoch_forks,fd_discof)
$(call add-objs,fd_exec,fd_discof)
ifdef FD_HAS_SSE
ifdef FD_HAS_ZSTD # required to load snapshot
$(call add-objs,fd_replay_tile,fd_discof)
else
$(warning "zstd not installed, skipping replay")
endif
endif
endif
