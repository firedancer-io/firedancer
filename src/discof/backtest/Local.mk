ifdef FD_HAS_HOSTED
# firedancer-dev only (backtest command)
$(call add-objs,fd_backtest_src fd_backtest_src_pcap fd_backtest_tile fd_libc_zstd fd_shredcap_trim,fd_firedancer_dev)
$(call make-unit-test,test_libc_zstd,test_libc_zstd fd_libc_zstd,fd_util)
$(call run-unit-test,test_libc_zstd)
$(call make-unit-test,test_shredcap_trim,test_shredcap_trim fd_shredcap_trim fd_backtest_src fd_backtest_src_pcap fd_libc_zstd,fd_ballet fd_util_extra fd_util)
$(call run-unit-test,test_shredcap_trim)

endif
