ifdef FD_HAS_ALLOCA
$(call add-objs,fd_echo_tile,fddev_shared)
$(call add-objs,fd_trtt_tile,fddev_shared)
ifdef FD_HAS_DOUBLE
$(call add-objs,tile_rtt,fddev_shared)
endif
endif
