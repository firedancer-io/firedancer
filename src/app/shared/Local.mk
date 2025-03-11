ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_INT128

$(call make-lib,fdctl_shared)

$(call add-hdrs,fd_cap_chk.h)
$(call add-hdrs,fd_sys_util.h)
$(call add-hdrs,fd_net_util.h)
$(call add-hdrs,fd_file_util.h)

$(call add-objs,fd_config fd_config_parse,fdctl_shared)
$(call make-unit-test,test_config_parse,test_config_parse,fd_fdctl fdctl_shared fd_ballet fd_util)
$(call make-fuzz-test,fuzz_fdctl_config,fuzz_fdctl_config,fd_fdctl fdctl_shared fd_ballet fd_util)

$(call add-objs,commands/help,fdctl_shared)
$(call add-objs,commands/keys,fdctl_shared)
$(call add-objs,commands/mem,fdctl_shared)
$(call add-objs,commands/netconf,fdctl_shared)
$(call add-objs,commands/ready,fdctl_shared)
$(call add-objs,commands/set_identity,fdctl_shared)
$(call add-objs,commands/version,fdctl_shared)
$(call add-objs,commands/configure/configure,fdctl_shared)
$(call add-objs,commands/configure/ethtool-channels,fdctl_shared)
$(call add-objs,commands/configure/ethtool-gro,fdctl_shared)
$(call add-objs,commands/configure/ethtool-loopback,fdctl_shared)
$(call add-objs,commands/configure/hugetlbfs,fdctl_shared)
$(call add-objs,commands/configure/hyperthreads,fdctl_shared)
$(call add-objs,commands/configure/ledger,fdctl_shared)
$(call add-objs,commands/configure/sysctl,fdctl_shared)
$(call add-objs,commands/monitor/monitor commands/monitor/helper,fdctl_shared)
$(call add-objs,commands/run/run commands/run/run1,fdctl_shared)
ifndef FD_HAS_NO_AGAVE
$(call add-objs,commands/run/run_agave,fdctl_shared)
endif

$(call add-objs,fd_cap_chk,fdctl_shared)
$(call add-objs,fd_file_util,fdctl_shared)
$(call add-objs,fd_sys_util,fdctl_shared)
$(call add-objs,fd_net_util,fdctl_shared)

endif
endif
endif
