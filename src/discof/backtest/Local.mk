ifdef FD_HAS_HOSTED
$(call add-objs,fd_backtest_src,fd_discof)
$(call add-objs,fd_backtest_src_pcap,fd_discof)

$(call add-objs,fd_backtest_tile,fd_discof)

ifdef FD_HAS_ZSTD
$(call add-objs,fd_libc_zstd,fd_discof)
$(call make-unit-test,test_libc_zstd,test_libc_zstd,fd_discof fd_util)
$(call run-unit-test,test_libc_zstd)
endif

endif
