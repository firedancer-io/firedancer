ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_snapshot_restore.h)
$(call add-objs,fd_snapshot_restore,fd_flamenco)

$(call add-hdrs,fd_snapshot_http.h)
$(call add-objs,fd_snapshot_http,fd_flamenco)
$(call make-unit-test,test_snapshot_http,test_snapshot_http,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_snapshot_http)
$(call make-fuzz-test,fuzz_snapshot_http,fuzz_snapshot_http,fd_flamenco fd_funk fd_ballet fd_util)

$(call add-hdrs,fd_snapshot_load.h)
$(call add-objs,fd_snapshot_load,fd_flamenco)

$(call make-bin,fd_snapshot,fd_snapshot_main,fd_flamenco fd_funk fd_ballet fd_util)
endif
