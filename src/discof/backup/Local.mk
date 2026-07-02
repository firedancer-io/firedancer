$(call add-objs,fd_snapmk_tile fd_snapzp_tile fd_snaprd_tile,fd_discof)
$(call add-objs,fd_backup_cache,fd_discof)
$(call add-objs,fd_ssmanifest_writer fd_txncache_writer,fd_discof)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call make-unit-test,test_snapmk_tile,test_snapmk_tile,fd_discof fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
$(call run-unit-test,test_snapmk_tile)
$(call make-unit-test,test_snapzp_tile,test_snapzp_tile,fd_discof fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
$(call run-unit-test,test_snapzp_tile)
$(call make-unit-test,test_snap_roundtrip,test_snap_roundtrip,fd_discof fd_flamenco_test fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
endif
endif
