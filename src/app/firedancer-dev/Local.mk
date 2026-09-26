ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE

.PHONY: firedancer-dev

$(call add-objs,commands/gossip,fd_firedancer_dev)
$(call add-objs,commands/bench,fd_firedancer_dev)
$(call add-objs,commands/dev,fd_firedancer_dev)
$(call add-objs,commands/backtest,fd_firedancer_dev)
$(call add-objs,commands/snapshot_load,fd_firedancer_dev)
$(call add-objs,commands/repair,fd_firedancer_dev)
$(call add-objs,commands/rotor,fd_firedancer_dev)
$(call add-objs,commands/tower,fd_firedancer_dev)
$(call add-objs,commands/ipecho_server,fd_firedancer_dev)
$(call add-objs,commands/gossip_dump,fd_firedancer_dev)
$(call add-objs,commands/reasm,fd_firedancer_dev)
$(call add-objs,commands/forktest/forktest commands/forktest/fd_forktest_tile,fd_firedancer_dev)

ifdef FD_ARCH_SUPPORTS_SANDBOX
# Programs transpiled by `firedancer-dev snapshot-load --transpile`
FD_TRANSPILED_LIB:=$(wildcard $(BASEDIR)/transpiled/x86/libfd_transpiled.a)
$(call make-bin,firedancer-dev,main,fd_firedancer_dev fd_firedancer fddev_shared fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_transpiler fd_vm fd_flamenco fd_waltz_test fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util_extra fd_util,$(FD_TRANSPILED_LIB))
$(OBJDIR)/bin/firedancer-dev: $(FD_TRANSPILED_LIB)
$(call make-integration-test,test_firedancer_dev,tests/test_firedancer_dev,fd_firedancer_dev fd_firedancer fddev_shared fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_waltz_test fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util_extra fd_util)
$(call run-integration-test,test_firedancer_dev)
endif

endif
endif
endif
endif
