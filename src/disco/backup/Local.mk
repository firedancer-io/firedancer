$(call add-objs,fd_snap_pool,fd_disco)
$(call add-objs,fd_ssmanifest_writer fd_txncache_writer,fd_disco)

ifdef FD_HAS_ATOMIC
$(call add-objs,fd_snapmk_tile fd_snapzp_tile fd_snaprd_tile,fd_disco)
$(call add-objs,fd_backup_cache,fd_disco)
ifdef FD_HAS_LINUX
$(call add-objs,fd_snapsv_tile,fd_disco)
$(call make-unit-test,test_snapsv,test_snapsv,fd_disco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_snapsv)
$(call make-unit-test,test_snapsv_tile,test_snapsv_tile,fd_disco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_snapsv_tile)
endif # FD_HAS_LINUX
endif # FD_HAS_ATOMIC

ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call make-unit-test,test_snap_roundtrip,test_snap_roundtrip,fd_disco fd_flamenco_test fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_snap_roundtrip)
ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_backup_disk,test_backup_disk,fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_backup_disk)
$(call make-unit-test,test_snapzp_tile,test_snapzp_tile,fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_snapzp_tile)
$(call make-unit-test,test_snaprd_tile,test_snaprd_tile,fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_snaprd_tile)
endif # FD_HAS_ATOMIC
endif # FD_HAS_INT128
endif # FD_HAS_HOSTED
