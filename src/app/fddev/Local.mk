ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128

include src/app/fdctl/with-version.mk

.PHONY: fddev run monitor $(OBJDIR)/lib/libsolana_genesis.a
$(call make-bin-rust,fddev,main main1 dev dev1 txn bench spammer dump flame tiles/fd_bencho tiles/fd_benchg tiles/fd_benchs configure/netns configure/keys configure/kill configure/genesis,fd_fdctl fd_fddev fd_disco fd_flamenco fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util solana_validator solana_genesis)

# TODO: There's a linker error due to the #[global_allocator] when including these files from a library
# so for now they are redeclared.
# fddev core
# $(call add-objs,main1 dev dev1 txn bench dump flame,fd_fddev)

# fddev tiles
# $(call add-objs,tiles/fd_bencho,fd_fddev)
# $(call add-objs,tiles/fd_benchg,fd_fddev)
# $(call add-objs,tiles/fd_benchs,fd_fddev)

# fddev configure stages
# $(call add-objs,configure/netns,fd_fddev)
# $(call add-objs,configure/keys,fd_fddev)
# $(call add-objs,configure/kill,fd_fddev)
# $(call add-objs,configure/genesis,fd_fddev)

# $(call make-bin-rust,fddev,main,fd_fdctl fd_fddev fd_disco fd_flamenco fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util solana_validator solana_genesis)

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

# TODO: There's a linker error due to the #[global_allocator] when including these files from a library
# so for now they are redeclared.
$(call make-integration-test,test_fddev,tests/test_fddev main1 dev dev1 txn bench spammer dump flame tiles/fd_bencho tiles/fd_benchg tiles/fd_benchs configure/netns configure/keys configure/kill configure/genesis,fd_fdctl fd_fddev fd_disco fd_flamenco fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util solana_validator solana_genesis)
$(call run-integration-test,test_fddev)

endif
endif
endif
endif
