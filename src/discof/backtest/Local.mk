$(call add-objs,fd_backtest_shredcap,fd_discof)
$(call make-unit-test,test_backtest_shredcap,test_backtest_shredcap,fd_discof fd_ballet fd_util)

ifdef FD_HAS_ALLOCA
$(call add-objs,fd_backtest_tile,fd_discof)
endif

ifdef FD_HAS_ZSTD
$(call add-objs,fd_libc_zstd,fd_discof)
$(call make-unit-test,test_libc_zstd,test_libc_zstd,fd_discof fd_util)
$(call run-unit-test,test_libc_zstd)
endif

ifdef FD_HAS_ROCKSDB
$(call add-objs,fd_backtest_rocksdb,fd_discof)
$(call make-bin,fd_blockstore2shredcap,fd_blockstore2shredcap,fd_discof fd_flamenco fd_ballet fd_util,$(ROCKSDB_LIBS))
endif
