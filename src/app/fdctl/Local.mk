ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_X86
ifdef FD_HAS_DOUBLE

.PHONY: fdctl run monitor cargo

$(call add-objs,main1 config security utility run/run run/tiles/dedup run/tiles/pack run/tiles/serve run/tiles/verify keygen ready monitor/monitor monitor/helper configure/configure configure/large_pages configure/sysctl configure/shmem configure/xdp configure/xdp_leftover configure/ethtool configure/workspace_leftover configure/workspace,fd_fdctl)
$(call make-bin-rust,fdctl,main,fd_fdctl fd_disco fd_ballet fd_tango fd_util fd_quic solana_validator_fd)
$(OBJDIR)/obj/app/fdctl/configure/xdp.o: src/tango/xdp/fd_xdp_redirect_prog.o
$(OBJDIR)/obj/app/fdctl/config.o: src/app/fdctl/config/default.toml

# Phony target to always rerun cargo build ... it will detect if anything
# changed on the library side.
cargo:

ifeq ($(RUST_PROFILE),release)
solana/target/$(RUST_PROFILE)/libsolana_validator_fd.a: cargo
	cd ./solana && env --unset=LDFLAGS ./cargo build --release -p solana-validator-fd
else
solana/target/$(RUST_PROFILE)/libsolana_validator_fd.a: cargo
	cd ./solana && env --unset=LDFLAGS ./cargo build -p solana-validator-fd
endif

$(OBJDIR)/lib/libsolana_validator_fd.a: solana/target/$(RUST_PROFILE)/libsolana_validator_fd.a
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/libsolana_validator_fd.a $@

fdctl: $(OBJDIR)/bin/fdctl

endif
endif
endif
endif
