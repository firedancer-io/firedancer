ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_snapshot.h)
$(call add-objs,fd_snapshot_restore,fd_flamenco)
$(call make-bin,fd_snapshot,fd_snapshot_main,fd_flamenco fd_funk fd_ballet fd_util)
endif
