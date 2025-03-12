ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128
ifdef FD_HAS_SSE

include src/app/fdctl/with-version.mk

.PHONY: fddev run monitor

$(call add-objs,main1 dev1,fd_fddev)

ifdef FD_HAS_NO_AGAVE
ifdef FD_HAS_SECP256K1
$(call make-bin,fddev,main,fd_fddev fd_fdctl fddev_shared fdctl_shared fd_discof fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util external_functions, $(SECP256K1_LIBS))
endif
else
$(call make-bin-rust,fddev,main,fd_fddev fd_fdctl fddev_shared fdctl_shared fd_discoh fd_disco agave_validator firedancer_plugin_bundle fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util)
endif

ifeq (run,$(firstword $(MAKECMDGOALS)))
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  ifeq ($(RUN_ARGS),)
    RUN_ARGS := dev --monitor
  endif
  $(eval $(RUN_ARGS):;@:)
endif

run: $(OBJDIR)/bin/fddev
	$(OBJDIR)/bin/fddev $(RUN_ARGS)

fddev: $(OBJDIR)/bin/fddev

ifeq (monitor,$(firstword $(MAKECMDGOALS)))
  MONITOR_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  ifeq ($(MONITOR_ARGS),)
    MONITOR_ARGS :=
  endif
  $(eval $(MONITOR_ARGS):;@:)
endif

monitor: bin
	$(OBJDIR)/bin/fddev monitor $(MONITOR_ARGS)

ifdef FD_HAS_NO_AGAVE
ifdef FD_HAS_SECP256K1
$(call make-integration-test,test_fddev,tests/test_fddev,fd_fddev fd_fdctl fddev_shared fdctl_shared fd_discof fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util external_functions, $(SECP256K1_LIBS))
endif
else
$(call make-integration-test,test_fddev,tests/test_fddev,fd_fddev fd_fdctl fddev_shared fdctl_shared fd_discoh fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util agave_validator firedancer_plugin_bundle)
endif
$(call run-integration-test,test_fddev)

endif
endif
endif
endif
endif
endif
