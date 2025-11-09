ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128

.PHONY: fddev run monitor

$(call add-objs,dev1,fd_fddev)
$(call add-objs,commands/configure/blockstore,fd_fddev)
$(call add-objs,commands/bench,fd_fddev)
$(call add-objs,commands/dev,fd_fddev)

$(call make-bin-rust,fddev,main,fd_fddev fd_fdctl fddev_shared fdctl_shared fdctl_platform fd_discoh fd_disco agave_validator fd_flamenco fd_funk fd_quic fd_tls fd_snp fd_reedsol fd_waltz fd_tango fd_ballet fd_util fdctl_version)

ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  ifeq ($(RUN_ARGS),)
    RUN_ARGS := dev --monitor
  endif
  $(eval $(RUN_ARGS):;@:)
endif

run: $(OBJDIR)/bin/fddev
	$(OBJDIR)/bin/fddev $(RUN_ARGS)

ifeq (monitor,$(firstword $(MAKECMDGOALS)))
  MONITOR_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  ifeq ($(MONITOR_ARGS),)
    MONITOR_ARGS :=
  endif
  $(eval $(MONITOR_ARGS):;@:)
endif

monitor: bin
	$(OBJDIR)/bin/fddev monitor $(MONITOR_ARGS)

$(call make-integration-test,test_fddev,tests/test_fddev,fd_fddev fd_fdctl fddev_shared fdctl_shared fdctl_platform fd_discoh fd_disco agave_validator fd_flamenco fd_funk fd_quic fd_tls fd_snp fd_reedsol fd_waltz fd_tango fd_ballet fd_util fdctl_version)
$(call run-integration-test,test_fddev)

endif
endif
endif
endif
endif
