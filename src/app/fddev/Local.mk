ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128

include src/app/fdctl/with-version.mk

.PHONY: fddev run monitor

# fddev core
$(call add-objs,main1 dev dev1 txn bench spammer dump flame,fd_fddev)

# fddev tiles
$(call add-objs,tiles/fd_bencho,fd_fddev)
$(call add-objs,tiles/fd_benchg,fd_fddev)
$(call add-objs,tiles/fd_benchs,fd_fddev)

# fddev configure stages
$(call add-objs,configure/netns,fd_fddev)
$(call add-objs,configure/keys,fd_fddev)
$(call add-objs,configure/kill,fd_fddev)
$(call add-objs,configure/genesis,fd_fddev)
$(call add-objs,configure/blockstore,fd_fddev)

ifdef FD_HAS_NO_SOLANA
$(call make-bin-rust,fddev,main external_functions,fd_fdctl fd_fddev fd_choreo fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util, $(SECP256K1_LIBS))
else
$(call make-bin-rust,fddev,main,fd_fdctl fd_fddev fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util solana_validator)
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

ifdef FD_HAS_NO_SOLANA
$(call make-integration-test,test_fddev,tests/test_fddev,fd_fdctl fd_fddev fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util external_functions)
else
$(call make-integration-test,test_fddev,tests/test_fddev,fd_fdctl fd_fddev fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util solana_validator)
endif
$(call run-integration-test,test_fddev)

endif
endif
endif
endif
