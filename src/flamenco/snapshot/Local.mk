ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_snapshot.h)
$(call add-objs,fd_snapshot_restore,fd_flamenco)
endif
