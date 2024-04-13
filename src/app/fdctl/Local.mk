ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE

.PHONY: fdctl cargo rust solana

$(call add-objs,main1 config caps utility topology keys ready mem spy help run/run run/tiles/tiles run/run1 run/run_solana run/tiles/tiles run/tiles/fd_net run/tiles/fd_metric run/tiles/fd_netmux run/tiles/fd_dedup run/tiles/fd_pack run/tiles/fd_quic run/tiles/fd_verify run/tiles/fd_poh run/tiles/fd_bank run/tiles/fd_shred run/tiles/fd_ext_store run/tiles/fd_gossip run/tiles/fd_sign run/tiles/fd_repair run/tiles/fd_tvu run/tiles/fd_store monitor/monitor monitor/helper configure/configure configure/large_pages configure/sysctl configure/shmem configure/xdp configure/xdp_leftover configure/ethtool configure/workspace_leftover configure/workspace,fd_fdctl)
$(call add-objs,run/topos/topos run/topos/tvu run/topos/firedancer,fd_fdctl)
$(call make-bin-rust,fdctl,main,fd_fdctl fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_ip fd_reedsol fd_ballet fd_tango fd_tvu fd_util solana_validator)
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
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_repair.o: src/app/fdctl/run/tiles/generated/repair_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_tvu.o: src/app/fdctl/run/tiles/generated/tvu_seccomp.h

# Phony target to always rerun cargo build ... it will detect if anything
# changed on the library side.
cargo:

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
cargo:
	cd ./solana && env --unset=LDFLAGS ./cargo build --release --lib -p solana-validator -p solana-genesis -p solana-cli --bin solana
else
cargo:
	cd ./solana && env --unset=LDFLAGS ./cargo build --lib -p solana-validator -p solana-genesis -p solana-cli --bin solana
endif

solana/target/$(RUST_PROFILE)/libsolana_validator.a: cargo

solana/target/$(RUST_PROFILE)/solana: cargo

$(OBJDIR)/lib/libsolana_validator.a: solana/target/$(RUST_PROFILE)/libsolana_validator.a
	$(MKDIR) $(dir $@) && cp solana/target/$(RUST_PROFILE)/libsolana_validator.a $@

fdctl: $(OBJDIR)/bin/fdctl

$(OBJDIR)/bin/solana: solana/target/$(RUST_PROFILE)/solana
	$(MKDIR) -p $(dir $@) && cp solana/target/$(RUST_PROFILE)/solana $@

rust: $(OBJDIR)/bin/solana

solana: $(OBJDIR)/bin/solana

endif
endif
endif
