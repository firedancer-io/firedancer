$(call add-objs,fd_snap_pool,fd_discof)
ifdef FD_HAS_ATOMIC
$(call add-objs,fd_snapmk_tile fd_snapzp_tile fd_snaprd_tile fd_snapsv_tile,fd_discof)
$(call add-objs,fd_backup_cache,fd_discof)
endif
$(call add-objs,fd_ssmanifest_writer fd_txncache_writer,fd_discof)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call make-unit-test,test_snap_roundtrip,test_snap_roundtrip,fd_discof fd_flamenco_test fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
$(call run-unit-test,test_snap_roundtrip)
ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_backup_disk,test_backup_disk,fd_discof fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
$(call run-unit-test,test_backup_disk)
endif
endif
endif
