ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
ifdef FD_HAS_ROCKSDB
$(call add-objs,fd_backtest_tile,fd_discof)
else
$(warning "rocksdb not installed, skipping backtest")
endif
endif
endif
