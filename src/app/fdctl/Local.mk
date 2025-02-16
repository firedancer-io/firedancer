ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128
ifdef FD_HAS_SSE

include src/app/fdctl/with-version.mk
$(info Using FIREDANCER_VERSION=$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH) ($(FIREDANCER_CI_COMMIT)))

# Always generate a version file
$(shell echo "#define FDCTL_MAJOR_VERSION $(FIREDANCER_VERSION_MAJOR)"                          >  src/app/fdctl/version2.h)
$(shell echo "#define FDCTL_MINOR_VERSION $(FIREDANCER_VERSION_MINOR)"                          >> src/app/fdctl/version2.h)
$(shell echo "#define FDCTL_PATCH_VERSION $(FIREDANCER_VERSION_PATCH)"                          >> src/app/fdctl/version2.h)
$(shell echo '#define FDCTL_COMMIT_REF_CSTR "$(FIREDANCER_CI_COMMIT)"'                          >> src/app/fdctl/version2.h)
$(shell echo "#define FDCTL_COMMIT_REF_U32 0x$(shell echo $(FIREDANCER_CI_COMMIT) | cut -c -8)" >> src/app/fdctl/version2.h)

# Update version.h only if version changed or doesn't exist
ifneq ($(shell cmp -s src/app/fdctl/version.h src/app/fdctl/version2.h && echo "same"),same)
src/app/fdctl/version.h: src/app/fdctl/version2.h
	cp -f src/app/fdctl/version2.h $@
endif

$(OBJDIR)/obj/app/fdctl/version.d: src/app/fdctl/version.h

.PHONY: fdctl cargo-validator cargo-solana cargo-ledger-tool cargo-plugin-bundle rust solana check-agave-hash frontend

# fdctl core
$(call add-objs,main1 config config_parse caps utility keys ready set_identity mem help version,fd_fdctl)
$(call add-objs,netconf,fd_fdctl)
$(call add-objs,run/run run/run1 run/run_agave,fd_fdctl)
$(call add-objs,monitor/monitor monitor/helper,fd_fdctl)
$(call make-fuzz-test,fuzz_fdctl_config,fuzz_fdctl_config,fd_fdctl fd_ballet fd_util)

# fdctl tiles
$(call add-objs,run/tiles/fd_net,fd_fdctl)
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
$(call add-objs,run/tiles/fd_bundle,fd_fdctl)
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
$(call add-objs,run/tiles/fd_batch,fd_fdctl)
$(call add-objs,run/tiles/fd_batch_thread,fd_fdctl)
$(call add-objs,run/tiles/fd_exec,fd_fdctl)
endif

# fdctl topologies
$(call add-objs,run/topos/fd_topos_common,fd_fdctl)
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
$(call add-objs,configure/ethtool-loopback,fd_fdctl)

ifdef FD_HAS_NO_AGAVE
ifdef FD_HAS_SECP256K1
$(call make-lib,external_functions)
$(call add-objs,external_functions,external_functions)
$(call make-bin-rust,fdctl,main,fd_fdctl fd_choreo fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util external_functions, $(SECP256K1_LIBS))
endif
else
$(call make-bin-rust,fdctl,main,fd_fdctl fd_disco fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util agave_validator firedancer_plugin_bundle)
endif
$(call make-unit-test,test_tiles_verify,run/tiles/test_verify,fd_ballet fd_tango fd_util)
$(call run-unit-test,test_tiles_verify)
$(call make-unit-test,test_config_parse,test_config_parse,fd_fdctl fd_ballet fd_util)

$(OBJDIR)/obj/app/fdctl/configure/xdp.o: src/waltz/xdp/fd_xdp_redirect_prog.o
$(OBJDIR)/obj/app/fdctl/config_parse.o: src/app/fdctl/config/default.toml
$(OBJDIR)/obj/app/fdctl/config_parse.o: src/app/fdctl/config/default-firedancer.toml
$(OBJDIR)/obj/app/fdctl/run/tiles/fd_gui.o: book/public/fire.svg

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
cargo-plugin-bundle: check-agave-hash

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
cargo-plugin-bundle:
    cd ./plugin/bundle && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --lib -p firedancer-plugin-bundle
cargo-validator:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --lib -p agave-validator
cargo-solana:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --bin solana
cargo-ledger-tool:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --release --bin agave-ledger-tool
else ifeq ($(RUST_PROFILE),release-with-debug)
cargo-plugin-bundle:
	cd ./plugin/bundle && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ../../agave/cargo build --profile=release-with-debug --lib -p firedancer-plugin-bundle
cargo-validator:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --lib -p agave-validator
cargo-solana:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --bin solana
cargo-ledger-tool:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --profile=release-with-debug --bin agave-ledger-tool
else
cargo-plugin-bundle:
    cd ./plugin/bundle && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" ./cargo build --lib -p firedancer-plugin-bundle
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

plugin/bundle/target/$(RUST_PROFILE)/libfiredancer_plugin_bundle.a: cargo-plugin-bundle
	@sleep 0.1

agave/target/$(RUST_PROFILE)/solana: cargo-solana

agave/target/$(RUST_PROFILE)/agave-ledger-tool: cargo-ledger-tool

$(OBJDIR)/lib/libagave_validator.a: agave/target/$(RUST_PROFILE)/libagave_validator.a
	$(MKDIR) $(dir $@) && cp agave/target/$(RUST_PROFILE)/libagave_validator.a $@

$(OBJDIR)/lib/libfiredancer_plugin_bundle.a: plugin/bundle/target/$(RUST_PROFILE)/libfiredancer_plugin_bundle.a
	$(MKDIR) $(dir $@) && cp plugin/bundle/target/$(RUST_PROFILE)/libfiredancer_plugin_bundle.a $@

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
	> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "/* THIS FILE WAS GENERATED BY make frontend. DO NOT EDIT BY HAND! */" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "#include \"http_import_dist.h\"" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	counter=0; \
	for file in $$(find src/app/fdctl/dist -type f | sort); do \
		echo "FD_IMPORT_BINARY( file$$counter, \"$$file\" );" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		counter=$$((counter + 1)); \
	done; \
	echo "" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "fd_http_static_file_t STATIC_FILES[] = {" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	counter=0; \
	for file in $$(find src/app/fdctl/dist -type f | sort); do \
		stripped_file=$$(echo $$file | sed 's|^src/app/fdctl/dist/||'); \
		echo "    {" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		echo "        .name = \"/$$stripped_file\"," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		echo "        .data = file$$counter," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		echo "        .data_len = &file$${counter}_sz," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		echo "    }," >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
		counter=$$((counter + 1)); \
	done; \
	echo "    {0}" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \
	echo "};" >> src/app/fdctl/run/tiles/generated/http_import_dist.c; \

endif
endif
endif
endif
endif
endif
