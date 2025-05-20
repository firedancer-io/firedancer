ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_SSE

$(call make-lib,fddev_shared)

# fddev boot
$(call add-objs,boot/fd_dev_boot,fddev_shared)

# fddev actions
$(call add-objs,commands/bench/bench,fddev_shared)
$(call add-objs,commands/bundle_client,fddev_shared)
$(call add-objs,commands/dev,fddev_shared)
$(call add-objs,commands/dump,fddev_shared)
$(call add-objs,commands/flame,fddev_shared)
$(call add-objs,commands/load,fddev_shared)
$(call add-objs,commands/pktgen/pktgen,fddev_shared)
$(call add-objs,commands/txn,fddev_shared)
$(call add-objs,commands/wksp,fddev_shared)

# fddev tiles
$(call add-objs,commands/bench/fd_bencho,fddev_shared)
$(call add-objs,commands/bench/fd_benchg,fddev_shared)
$(call add-objs,commands/bench/fd_benchs,fddev_shared)
$(call add-objs,commands/pktgen/fd_pktgen_tile,fddev_shared)

# fddev configure stages
$(call add-objs,commands/configure/netns,fddev_shared)
$(call add-objs,commands/configure/keys,fddev_shared)
$(call add-objs,commands/configure/kill,fddev_shared)
$(call add-objs,commands/configure/genesis,fddev_shared)

endif
endif
endif
