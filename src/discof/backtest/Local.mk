ifdef FD_HAS_ROCKSDB
$(call add-objs,fd_backtest_rocksdb fd_backtest_tile,fd_discof)
$(call make-bin,fd_blockstore2shredcap,fd_blockstore2shredcap,fd_discof fd_flamenco fd_ballet fd_util,$(ROCKSDB_LIBS))
else
$(warning "rocksdb not installed, skipping backtest")
endif
