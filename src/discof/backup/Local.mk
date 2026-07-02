$(call add-objs,fd_ssmanifest_writer fd_txncache_writer,fd_discof)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call make-unit-test,test_snap_roundtrip,test_snap_roundtrip,fd_discof fd_flamenco_test fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
endif
endif
