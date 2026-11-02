ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX

$(call make-lib,fd_app_shared)

$(call add-objs,fd_bootinfo,fd_app_shared)
$(call add-objs,fd_config fd_config_parse fd_auto_net fd_config_json,fd_app_shared)
$(call add-objs,fd_obj_callbacks,fd_app_shared)
$(call make-unit-test,test_config_parse,test_config_parse,fd_firedancer fd_app_shared fd_app_platform fd_disco fd_waltz fd_ballet fd_tango fd_util)
$(call run-unit-test,test_config_parse)
$(call make-unit-test,test_auto_net,test_auto_net,fd_firedancer fd_app_shared fd_app_platform fd_disco fd_waltz fd_ballet fd_tango fd_util)
$(call run-unit-test,test_auto_net)
$(call make-unit-test,test_config_json,test_config_json,fd_firedancer fd_app_shared fd_app_platform fd_disco fd_waltz fd_ballet fd_tango fd_util)
$(call run-unit-test,test_config_json)
$(call make-fuzz-test,fuzz_config_parse,fuzz_config_parse,fd_firedancer fd_app_shared fd_app_platform fd_disco fd_waltz fd_ballet fd_tango fd_util)

$(call add-objs,boot/fd_boot,fd_app_shared)

$(call add-objs,commands/help,fd_app_shared)
$(call add-objs,commands/keys,fd_app_shared)
$(call add-objs,commands/mem,fd_app_shared)
$(call add-objs,commands/metrics,fd_app_shared)
$(call add-objs,commands/netconf,fd_app_shared)
$(call add-objs,commands/ps,fd_app_shared)
$(call add-objs,commands/ready,fd_app_shared)
$(call add-objs,commands/version,fd_app_shared)
$(call add-objs,commands/configure/configure,fd_app_shared)
$(call add-objs,commands/configure/mlx5,fd_app_shared)
$(call add-objs,commands/configure/bonding,fd_app_shared)
$(call add-objs,commands/configure/ethtool-channels,fd_app_shared)
$(call add-objs,commands/configure/ethtool-offloads,fd_app_shared)
$(call add-objs,commands/configure/ethtool-loopback,fd_app_shared)
$(call add-objs,commands/configure/irq-affinity,fd_app_shared)
$(call add-objs,commands/configure/irq-balance,fd_app_shared)
$(call add-objs,commands/configure/fd_ethtool_ioctl,fd_app_shared)
$(call add-objs,commands/configure/fd_irqbalance_client,fd_app_shared)
$(call add-objs,commands/configure/hugetlbfs,fd_app_shared)
$(call add-objs,commands/configure/hyperthreads,fd_app_shared)
$(call add-objs,commands/configure/sysctl,fd_app_shared)
$(call add-objs,commands/configure/sysfs-poll,fd_app_shared)
$(call add-objs,commands/configure/snapshots,fd_app_shared)
$(call add-objs,commands/configure/fd_cpu_isolation,fd_app_shared)
$(call add-objs,commands/configure/kworkers,fd_app_shared)
$(call add-objs,commands/configure/cpuset,fd_app_shared)
$(call add-objs,commands/configure/nohz-full,fd_app_shared)
$(call add-objs,commands/configure/rcu-nocbs,fd_app_shared)
$(call add-objs,commands/configure/console,fd_app_shared)
ifdef FD_HAS_ALLOCA
$(call add-objs,commands/monitor/monitor commands/monitor/helper,fd_app_shared)
$(call add-objs,commands/watch/watch,fd_app_shared)
endif # FD_HAS_ALLOCA
$(call add-objs,commands/run/run commands/run/run1,fd_app_shared)

endif
endif
