ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128
ifdef FD_HAS_SSE

include src/app/fdctl/with-version.mk
$(info Using FIREDANCER_VERSION=$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH))

src/app/fdctl/version.h: src/app/fdctl/version.mk
	echo "#define FDCTL_MAJOR_VERSION $(FIREDANCER_VERSION_MAJOR)UL" > $@
	echo "#define FDCTL_MINOR_VERSION $(FIREDANCER_VERSION_MINOR)UL" >> $@
	echo "#define FDCTL_PATCH_VERSION $(FIREDANCER_VERSION_PATCH)UL" >> $@
$(OBJDIR)/obj/app/fdctl/version.d: src/app/fdctl/version.h

.PHONY: fdctl cargo-validator cargo-solana cargo-ledger-tool rust solana check-agave-hash frontend

# fdctl core
$(call add-objs,main1 config config_parse caps utility keys ready mem spy help version,fd_fdctl)
$(call add-objs,run/run run/run1 run/run_agave,fd_fdctl)
$(call add-objs,monitor/monitor monitor/helper,fd_fdctl)
$(call make-fuzz-test,fuzz_fdctl_config,fuzz_fdctl_config,fd_fdctl fd_ballet fd_util)

# fdctl tiles
$(call add-objs,run/tiles/fd_net,fd_fdctl)
$(call add-objs,run/tiles/fd_quic,fd_fdctl)
$(call add-objs,run/tiles/fd_verify,fd_fdctl)
$(call add-objs,run/tiles/fd_dedup,fd_fdctl)
$(call add-objs,run/tiles/fd_resolv,fd_fdctl)
$(call add-objs,run/tiles/fd_pack,fd_fdctl)
$(call add-objs,run/tiles/fd_bank,fd_fdctl)
$(call add-objs,run/tiles/fd_poh,fd_fdctl)
$(call add-objs,run/tiles/fd_shred,fd_fdctl)
$(call add-objs,run/tiles/fd_store,fd_fdctl)
$(call add-objs,run/tiles/fd_sign,fd_fdctl)
$(call add-objs,run/tiles/fd_cswtch,fd_fdctl)
$(call add-objs,run/tiles/fd_metric,fd_fdctl)
$(call add-objs,run/tiles/fd_gui,fd_fdctl)
$(call add-objs,run/tiles/fd_plugin,fd_fdctl)
$(call add-objs,run/tiles/generated/http_import_dist,fd_fdctl)
$(call add-objs,run/tiles/fd_blackhole,fd_fdctl)

ifdef FD_HAS_NO_AGAVE
$(call add-objs,run/tiles/fd_repair,fd_fdctl)
$(call add-objs,run/tiles/fd_gossip,fd_fdctl)
$(call add-objs,run/tiles/fd_store_int,fd_fdctl)
$(call add-objs,run/tiles/fd_replay,fd_fdctl)
$(call add-objs,run/tiles/fd_replay_thread,fd_fdctl)
$(call add-objs,run/tiles/fd_poh_int,fd_fdctl)
$(call add-objs,run/tiles/fd_sender,fd_fdctl)
$(call add-objs,run/tiles/fd_eqvoc,fd_fdctl)
$(call add-objs,run/tiles/fd_rpcserv,fd_fdctl)
endif

# fdctl topologies
ifdef FD_HAS_NO_AGAVE
$(call add-objs,run/topos/fd_firedancer,fd_fdctl)
else
$(call add-objs,run/topos/fd_frankendancer,fd_fdctl)
endif

# fdctl configure stages
$(call add-objs,configure/configure,fd_fdctl)
$(call add-objs,configure/hugetlbfs,fd_fdctl)
$(call add-objs,configure/sysctl,fd_fdctl)
$(call add-objs,configure/ethtool-channels,fd_fdctl)
$(call add-objs,configure/ethtool-gro,fd_fdctl)

ifdef FD_HAS_NO_AGAVE
ifdef FD_HAS_SECP256K1
$(call make-lib,external_functions)
$(call add-objs,external_functions,external_functions)
$(call make-bin-rust,fdctl,main,fd_fdctl fd_choreo fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_ip fd_reedsol fd_ballet fd_waltz fd_tango fd_util external_functions, $(SECP256K1_LIBS))
endif
else
$(call make-bin-rust,fdctl,main,fd_fdctl fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_ip fd_reedsol fd_ballet fd_waltz fd_tango fd_util agave_validator)
endif
$(call make-unit-test,test_tiles_verify,run/tiles/test_verify,fd_ballet fd_tango fd_util)
$(call run-unit-test,test_tiles_verify)
$(call make-unit-test,test_config_parse,test_config_parse,fd_fdctl fd_ballet fd_util)

$(OBJDIR)/obj/app/fdctl/configure/xdp.o: src/waltz/xdp/fd_xdp_redirect_prog.o
$(OBJDIR)/obj/app/fdctl/config_parse.o: src/app/fdctl/config/default.toml
$(OBJDIR)/obj/app/fdctl/config_parse.o: src/app/fdctl/config/default-firedancer.toml
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_gui.o: book/public/fire.svg

$(OBJDIR)/obj/app/fdctl/run/run.o: src/app/fdctl/run/generated/main_seccomp.h src/app/fdctl/run/generated/pidns_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_dedup.o: src/app/fdctl/run/tiles/generated/dedup_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_net.o: src/app/fdctl/run/tiles/generated/net_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_pack.o: src/app/fdctl/run/tiles/generated/pack_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_quic.o: src/app/fdctl/run/tiles/generated/quic_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_shred.o: src/app/fdctl/run/tiles/generated/shred_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_verify.o: src/app/fdctl/run/tiles/generated/verify_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_metric.o: src/app/fdctl/run/tiles/generated/metric_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_cswtch.o: src/app/fdctl/run/tiles/generated/cswtch_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_gui.o: src/app/fdctl/run/tiles/generated/gui_seccomp.h src/app/fdctl/run/tiles/generated/http_import_dist.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_plugin.o: src/app/fdctl/run/tiles/generated/plugin_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_sign.o: src/app/fdctl/run/tiles/generated/sign_seccomp.h
ifdef FD_HAS_NO_AGAVE
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_repair.o: src/app/fdctl/run/tiles/generated/repair_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_gossip.o: src/app/fdctl/run/tiles/generated/gossip_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_store_int.o: src/app/fdctl/run/tiles/generated/store_int_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_replay.o: src/app/fdctl/run/tiles/generated/replay_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_sender.o: src/app/fdctl/run/tiles/generated/sender_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_eqvoc.o: src/app/fdctl/run/tiles/generated/eqvoc_seccomp.h
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_rpcserv.o: src/app/fdctl/run/tiles/generated/rpcserv_seccomp.h
endif

check-agave-hash:
	@$(eval AGAVE_COMMIT_LS_TREE=$(shell git ls-tree HEAD | grep agave | awk '{print $$3}'))
	@$(eval AGAVE_COMMIT_SUBMODULE=$(shell git --git-dir=agave/.git --work-tree=agave rev-parse HEAD))
	@if [ "$(AGAVE_COMMIT_LS_TREE)" != "$(AGAVE_COMMIT_SUBMODULE)" ]; then \
		echo "Error: agave submodule is not up to date. Please run \`git submodule update\` before building"; \
		exit 1; \
	fi

# Phony target to always rerun cargo build ... it will detect if anything
# changed on the library side.
cargo-validator: check-agave-hash
cargo-solana: check-agave-hash
cargo-ledger-tool: check-agave-hash

# Cargo build cannot cache the prior build if the command line changes,
# for example if we did,
#
#  1. cargo build --release --lib -p agave-validator
#  2. cargo build --release --lib -p solana-genesis
#  3. cargo build --release --lib -p agave-validator
#
# The third build would rebuild from some partial state. This is not
# great for build times, so we always build all the libs and bins
# with one cargo command, even if the dependency could be more fine
# grained.
ifeq ($(RUST_PROFILE),release)
cargo-validator:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --lib -p agave-validator
cargo-solana:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --bin solana
cargo-ledger-tool:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --bin agave-ledger-tool
else ifeq ($(RUST_PROFILE),release-with-debug)
cargo-validator:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --lib -p agave-validator
cargo-solana:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --bin solana
cargo-ledger-tool:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --bin agave-ledger-tool
else
cargo-validator:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --lib -p agave-validator
cargo-solana:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --bin solana
cargo-ledger-tool:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --bin agave-ledger-tool
endif

# We sleep as a workaround for a bizarre problem where the build system
# looks at the mtime of this file before `cargo build` has finished
# writing to it and updating the mtime. It will then sometimes see that
# the file is "older" than the fdctl binary and think it does not need
# to rebuild.
agave/target/$(RUST_PROFILE)/libagave_validator.a: cargo-validator
	@sleep 0.1

agave/target/$(RUST_PROFILE)/solana: cargo-solana

agave/target/$(RUST_PROFILE)/agave-ledger-tool: cargo-ledger-tool

$(OBJDIR)/lib/libagave_validator.a: agave/target/$(RUST_PROFILE)/libagave_validator.a
	$(MKDIR) $(dir $@) && cp agave/target/$(RUST_PROFILE)/libagave_validator.a $@

fdctl: $(OBJDIR)/bin/fdctl

$(OBJDIR)/bin/solana: agave/target/$(RUST_PROFILE)/solana
	$(MKDIR) -p $(dir $@) && cp agave/target/$(RUST_PROFILE)/solana $@

solana: $(OBJDIR)/bin/solana

$(OBJDIR)/bin/agave-ledger-tool: agave/target/$(RUST_PROFILE)/agave-ledger-tool
	$(MKDIR) -p $(dir $@) && cp agave/target/$(RUST_PROFILE)/agave-ledger-tool $@

agave-ledger-tool: $(OBJDIR)/bin/agave-ledger-tool

frontend:
	cd frontend && npm ci && npm run build
	rm -rf src/app/fdctl/dist
	mkdir -p src/app/fdctl/dist
	cp -r frontend/dist/* src/app/fdctl/dist
	> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "/* THIS FILE WAS GENERATED BY make frontend. DO NOT EDIT BY HAND! */" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "#ifndef HEADER_fd_src_app_fdctl_run_tiles_generated_http_import_dist_h" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "#define HEADER_fd_src_app_fdctl_run_tiles_generated_http_import_dist_h" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "#include \"../../../../../util/fd_util.h\"" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	counter=0; \
	for file in $$(find src/app/fdctl/dist -type f); do \
		counter=$$((counter + 1)); \
	done; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "struct fd_http_static_file {" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "    char const * name;" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "    uchar const * data;" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "    ulong const * data_len;" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "    uchar const * zstd_data;" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "    ulong const * zstd_data_len;" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "};" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "typedef struct fd_http_static_file fd_http_static_file_t;" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "extern fd_http_static_file_t STATIC_FILES[$$counter];" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	echo "#endif" >> src/app/fdctl/run/tiles/generated/http_import_dist.h; \
	> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "/* THIS FILE WAS GENERATED BY make frontend. DO NOT EDIT BY HAND! */" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "#include \"http_import_dist.h\"" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	counter=0; \
	for file in $$(find src/app/fdctl/dist -type f); do \
		if [[ "$$file" == *.svg || "$$file" == *.js || "$$file" == *.css ]]; then \
			zstd -19 -o "$$file.zstd" "$$file"; \
			echo "FD_IMPORT_BINARY( file$${counter}_zstd, \"$$file.zstd\" );" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		fi; \
		echo "FD_IMPORT_BINARY( file$$counter, \"$$file\" );" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		counter=$$((counter + 1)); \
	done; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "fd_http_static_file_t STATIC_FILES[] = {" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	counter=0; \
	for file in $$(find src/app/fdctl/dist -type f ! -name "*.zstd"); do \
		stripped_file=$$(echo $$file | sed 's|^src/app/fdctl/dist/||'); \
		echo "    {" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		echo "        .name = \"/$$stripped_file\"," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		echo "        .data = file$$counter," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		echo "        .data_len = &file$${counter}_sz," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		if [[ "$$file" == *.svg || "$$file" == *.js || "$$file" == *.css ]]; then \
			echo "        .zstd_data = file$${counter}_zstd," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
			echo "        .zstd_data_len = &file$${counter}_zstd_sz" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		else \
			echo "        .zstd_data = NULL," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
			echo "        .zstd_data_len = 0UL" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		fi; \
		echo "    }," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		counter=$$((counter + 1)); \
	done; \
	echo "};" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \

endif
endif
endif
endif
endif
endif
