$(call add-hdrs,fd_snapshot_base.h)
$(call add-objs,fd_snapshot_base,fd_flamenco)

ifdef FD_HAS_INT128
ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_snapshot_http.h)
$(call add-objs,fd_snapshot_http,fd_flamenco)
$(call make-unit-test,test_snapshot_http,test_snapshot_http,fd_flamenco fd_disco fd_waltz fd_ballet fd_util)
$(call run-unit-test,test_snapshot_http)
ifdef FD_HAS_THREADS
$(call make-fuzz-test,fuzz_snapshot_http,fuzz_snapshot_http,fd_flamenco fd_disco fd_waltz fd_ballet fd_util)
endif
endif

$(call add-hdrs,fd_snapshot_istream.h)
$(call add-objs,fd_snapshot_istream,fd_flamenco)

$(call add-hdrs,fd_snapshot_restore.h)
$(call add-objs,fd_snapshot_restore,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_snapshot_restore,test_snapshot_restore,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_snapshot_restore)
endif

ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_snapshot.h)
$(call add-objs,fd_snapshot,fd_flamenco)

$(call add-hdrs,fd_snapshot_loader.h)
$(call add-objs,fd_snapshot_loader,fd_flamenco)

# We are not building this because it currently iterates over all accounts in a Funk transaction,
# which is no longer supported.
# $(call make-bin,fd_snapshot,fd_snapshot_main,fd_flamenco fd_disco fd_funk fd_waltz fd_ballet fd_util,$(SECP256K1_LIBS))
endif
endif
