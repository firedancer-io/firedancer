ifdef FD_HAS_HOSTED
# firedancer-dev only (backtest/forktest commands)
$(call add-objs,fd_backtest_src fd_backtest_src_pcap fd_backtest_tile fd_libc_zstd,fd_firedancer_dev)
$(call make-unit-test,test_libc_zstd,test_libc_zstd fd_libc_zstd,fd_util)
$(call run-unit-test,test_libc_zstd)

endif
