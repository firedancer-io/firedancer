ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE

.PHONY: fddev run monitor
$(call make-bin-rust,fddev,main dev dev1 txn bench configure/netns configure/keys configure/kill configure/genesis,fd_fdctl fd_fddev fd_disco fd_flamenco fd_quic fd_tls fd_reedsol fd_ballet fd_tango fd_util solana_validator solana_genesis)

solana/target/$(RUST_PROFILE)/libsolana_genesis.a: cargo

$(OBJDIR)/lib/libsolana_genesis.a: solana/target/$(RUST_PROFILE)/libsolana_genesis.a
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/libsolana_genesis.a $@

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

endif
endif
endif
