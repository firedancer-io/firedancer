ifdef FD_HAS_INT128
ifdef FD_HAS_ROCKSDB
$(call add-objs,fd_backtest_rocksdb fd_backtest_tile,fd_discof)
$(call add-objs,fd_simulate_tile,fd_discof)
else
$(warning "rocksdb not installed, skipping backtest")
endif
endif
