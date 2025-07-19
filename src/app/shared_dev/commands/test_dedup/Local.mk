ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX # FIXME why is this needed
ifdef FD_HAS_AVX

$(call add-objs,test_dedup,fddev_shared)
$(call add-objs,test_dedup_rx_tile,fddev_shared)
$(call add-objs,test_dedup_tx_tile,fddev_shared)

endif
endif
endif
