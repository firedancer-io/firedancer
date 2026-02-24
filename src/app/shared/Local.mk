ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_INT128

$(call make-lib,fdctl_shared)

$(call add-objs,fd_config fd_config_parse,fdctl_shared)
$(call add-objs,fd_obj_callbacks,fdctl_shared)
$(call add-objs,fd_tile_unit_test,fdctl_shared)
$(call make-unit-test,test_config_parse,test_config_parse,fd_fdctl fdctl_shared fdctl_platform fd_disco fd_ballet fd_tango fd_util)
$(call run-unit-test,test_config_parse)
$(call make-fuzz-test,fuzz_fdctl_config,fuzz_fdctl_config,fd_fdctl fdctl_shared fdctl_platform fd_disco fd_ballet fd_tango fd_util)

$(call add-objs,boot/fd_boot,fdctl_shared)

$(call add-objs,commands/help,fdctl_shared)
$(call add-objs,commands/keys,fdctl_shared)
$(call add-objs,commands/mem,fdctl_shared)
$(call add-objs,commands/metrics,fdctl_shared)
$(call add-objs,commands/netconf,fdctl_shared)
$(call add-objs,commands/ready,fdctl_shared)
$(call add-objs,commands/set_identity,fdctl_shared)
$(call add-objs,commands/get_identity,fdctl_shared)
$(call add-objs,commands/version,fdctl_shared)
$(call add-objs,commands/configure/configure,fdctl_shared)
$(call add-objs,commands/configure/bonding,fdctl_shared)
$(call add-objs,commands/configure/ethtool-channels,fdctl_shared)
$(call add-objs,commands/configure/ethtool-offloads,fdctl_shared)
$(call add-objs,commands/configure/ethtool-loopback,fdctl_shared)
$(call add-objs,commands/configure/fd_ethtool_ioctl,fdctl_shared)
$(call add-objs,commands/configure/hugetlbfs,fdctl_shared)
$(call add-objs,commands/configure/hyperthreads,fdctl_shared)
$(call add-objs,commands/configure/sysctl,fdctl_shared)
$(call add-objs,commands/configure/sysfs-poll,fdctl_shared)
$(call add-objs,commands/configure/snapshots,fdctl_shared)
$(call add-objs,commands/monitor/monitor commands/monitor/helper,fdctl_shared)
$(call add-objs,commands/watch/watch,fdctl_shared)
$(call add-objs,commands/run/run commands/run/run1,fdctl_shared)

endif
endif
endif
