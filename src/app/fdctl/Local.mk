ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE

include src/app/fdctl/with-version.mk
$(info Using FIREDANCER_VERSION=$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH))

# When we don't have libsolana_validator.a in the PHONY list, make fails
# to realize that it has been updated. Not sure why this happens.
.PHONY: fdctl cargo-validator cargo-solana rust solana

# fdctl core
$(call add-objs,main1 config caps utility keys ready mem spy help,fd_fdctl)
$(call add-objs,run/run run/run1 run/run_solana,fd_fdctl)
$(call add-objs,monitor/monitor monitor/helper,fd_fdctl)

# fdctl tiles
$(call add-objs,run/tiles/fd_net,fd_fdctl)
$(call add-objs,run/tiles/fd_metric,fd_fdctl)
$(call add-objs,run/tiles/fd_netmux,fd_fdctl)
$(call add-objs,run/tiles/fd_dedup,fd_fdctl)
$(call add-objs,run/tiles/fd_pack,fd_fdctl)
$(call add-objs,run/tiles/fd_quic,fd_fdctl)
$(call add-objs,run/tiles/fd_verify,fd_fdctl)
$(call add-objs,run/tiles/fd_poh,fd_fdctl)
$(call add-objs,run/tiles/fd_bank,fd_fdctl)
$(call add-objs,run/tiles/fd_shred,fd_fdctl)
$(call add-objs,run/tiles/fd_store,fd_fdctl)
$(call add-objs,run/tiles/fd_sign,fd_fdctl)

# fdctl configure stages
$(call add-objs,configure/configure,fd_fdctl)
$(call add-objs,configure/hugetlbfs,fd_fdctl)
$(call add-objs,configure/sysctl,fd_fdctl)
$(call add-objs,configure/xdp,fd_fdctl)
$(call add-objs,configure/ethtool,fd_fdctl)
$(call add-objs,configure/workspace,fd_fdctl)

$(call make-bin-rust,fdctl,main,fd_fdctl fd_disco fd_flamenco fd_quic fd_tls fd_ip fd_reedsol fd_ballet fd_waltz fd_tango fd_util solana_validator)
$(call make-unit-test,test_tiles_verify,run/tiles/test_verify,fd_ballet fd_tango fd_util)
$(call run-unit-test,test_tiles_verify)

$(OBJDIR)/obj/app/fdctl/configure/xdp.o: src/waltz/xdp/fd_xdp_redirect_prog.o
$(OBJDIR)/obj/app/fdctl/config.o: src/app/fdctl/config/default.toml

$(OBJDIR)/obj/app/fdctl/run/run.o: src/app/fdctl/run/generated/main_seccomp.h src/app/fdctl/run/generated/pidns_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_dedup.o: src/app/fdctl/run/tiles/generated/dedup_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_net.o: src/app/fdctl/run/tiles/generated/net_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_netmux.o: src/app/fdctl/run/tiles/generated/netmux_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_pack.o: src/app/fdctl/run/tiles/generated/pack_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_quic.o: src/app/fdctl/run/tiles/generated/quic_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_shred.o: src/app/fdctl/run/tiles/generated/shred_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_verify.o: src/app/fdctl/run/tiles/generated/verify_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_metric.o: src/app/fdctl/run/tiles/generated/metric_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_sign.o: src/app/fdctl/run/tiles/generated/sign_seccomp.h

# Phony target to always rerun cargo build ... it will detect if anything
# changed on the library side.
cargo-validator:
cargo-solana:

# Cargo build cannot cache the prior build if the command line changes,
# for example if we did,
#
#  1. cargo build --release --lib -p solana-validator
#  2. cargo build --release --lib -p solana-genesis
#  3. cargo build --release --lib -p solana-validator
#
# The third build would rebuild from some partial state. This is not
# great for build times, so we always build all the libs and bins
# with one cargo command, even if the dependency could be more fine
# grained.
ifeq ($(RUST_PROFILE),release)
cargo-validator:
	cd ./solana && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --lib -p solana-validator
cargo-solana:
	cd ./solana && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --bin solana
else ifeq ($(RUST_PROFILE),release-with-debug)
cargo-validator:
	cd ./solana && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --lib -p solana-validator
cargo-solana:
	cd ./solana && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --bin solana
else
cargo-validator:
	cd ./solana && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --lib -p solana-validator
cargo-solana:
	cd ./solana && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --bin solana
endif

solana/target/$(RUST_PROFILE)/libsolana_validator.a: cargo-validator

solana/target/$(RUST_PROFILE)/solana: cargo-solana

$(OBJDIR)/lib/libsolana_validator.a: solana/target/$(RUST_PROFILE)/libsolana_validator.a
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/libsolana_validator.a $@

fdctl: $(OBJDIR)/bin/fdctl

$(OBJDIR)/bin/solana: solana/target/$(RUST_PROFILE)/solana
	$(MKDIR) -p $(dir $@) && cp solana/target/$(RUST_PROFILE)/solana $@

solana: $(OBJDIR)/bin/solana $(OBJDIR)/bin/solana

endif
endif
endif
