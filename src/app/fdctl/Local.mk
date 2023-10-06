ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_X86
ifdef FD_HAS_DOUBLE

.PHONY: fdctl cargo

$(call add-objs,main1 config caps utility run/run run/tiles/tiles run/tiles/net run/tiles/netmux run/tiles/dedup run/tiles/pack run/tiles/quic run/tiles/verify run/tiles/bank run/tiles/shred keygen ready monitor/monitor monitor/helper configure/configure configure/large_pages configure/sysctl configure/shmem configure/xdp configure/xdp_leftover configure/ethtool configure/workspace_leftover configure/workspace,fd_fdctl)
$(call make-bin-rust,fdctl,main,fd_fdctl fd_disco fd_flamenco fd_ip fd_reedsol fd_ballet fd_tango fd_util fd_quic solana_validator_fd)
$(OBJDIR)/obj/app/fdctl/configure/xdp.o: src/tango/xdp/fd_xdp_redirect_prog.o
$(OBJDIR)/obj/app/fdctl/config.o: src/app/fdctl/config/default.toml

# Phony target to always rerun cargo build ... it will detect if anything
# changed on the library side.
cargo:

ifeq ($(RUST_PROFILE),release)
solana/target/$(RUST_PROFILE)/libsolana_validator.a: cargo
	cd ./solana && env --unset=LDFLAGS ./cargo build --release --lib -p solana-validator

solana/target/$(RUST_PROFILE)/solana: cargo
	cd ./solana && env --unset=LDFLAGS ./cargo build --release --bin solana -p solana-cli
else
solana/target/$(RUST_PROFILE)/libsolana_validator.a: cargo
	cd ./solana && env --unset=LDFLAGS ./cargo build --lib -p solana-validator

solana/target/$(RUST_PROFILE)/solana: cargo
	cd ./solana && env --unset=LDFLAGS ./cargo build --bin solana -p solana-cli
endif

$(OBJDIR)/lib/libsolana_validator.a: solana/target/$(RUST_PROFILE)/libsolana_validator.a
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/libsolana_validator.a $@

fdctl: $(OBJDIR)/bin/fdctl

$(OBJDIR)/bin/solana: solana/target/$(RUST_PROFILE)/solana
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/solana $@

rust: $(OBJDIR)/bin/solana

endif
endif
endif
endif
