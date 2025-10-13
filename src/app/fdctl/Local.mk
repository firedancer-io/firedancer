include src/app/fdctl/with-version.mk
$(info Using FIREDANCER_VERSION=$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH) ($(FIREDANCER_CI_COMMIT)))
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

# Always generate a version file
include src/app/fdctl/version.h

ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_INT128

$(OBJDIR)/obj/app/fdctl/config.o: src/app/fdctl/config/default.toml

# fdctl core
$(call add-objs,topology,fd_fdctl)
$(call add-objs,config,fd_fdctl)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS

.PHONY: fdctl cargo-validator cargo-solana cargo-ledger-tool rust solana check-agave-hash

# fdctl comands
$(call add-objs,commands/run_agave,fd_fdctl)

# version
$(call make-lib,fdctl_version)
$(call add-objs,version,fdctl_version)

$(call make-bin-rust,fdctl,main,fd_fdctl fdctl_shared fdctl_platform fd_discoh fd_disco agave_validator fd_flamenco fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util fdctl_version)

check-agave-hash:
	@$(eval AGAVE_COMMIT_LS_TREE=$(shell git ls-tree HEAD | grep agave | awk '{print $$3}'))
	@$(eval AGAVE_COMMIT_SUBMODULE=$(shell git --git-dir=agave/.git --work-tree=agave rev-parse HEAD))
	@if [ "$(AGAVE_COMMIT_LS_TREE)" != "$(AGAVE_COMMIT_SUBMODULE)" ]; then \
		echo "Error: agave submodule is not up to date. Please run \`git submodule update\` before building"; \
		exit 1; \
	fi

update-rust-toolchain:
	@$(eval TOOLCHAIN_VERSION=$(shell sed -n 's/^channel = "\(.*\)"$$/\1/p' agave/rust-toolchain.toml))
	@$(eval TOOLCHAIN_EXISTS=$(shell rustup toolchain list | grep -c $(TOOLCHAIN_VERSION)))
	@if [ "$(TOOLCHAIN_EXISTS)" -eq 0 ]; then \
		echo "Installing rust toolchain $(TOOLCHAIN_VERSION)"; \
		rustup toolchain add $(TOOLCHAIN_VERSION); \
	fi

# Phony target to always rerun cargo build ... it will detect if anything
# changed on the library side.
cargo-validator: check-agave-hash update-rust-toolchain
cargo-solana: check-agave-hash update-rust-toolchain
cargo-ledger-tool: check-agave-hash update-rust-toolchain

# Currently, rocksdb does not compile with GCC 15. This hack will not be
# necessary once https://github.com/facebook/rocksdb/issues/13365 is fixed.
ifeq ($(CC),gcc)
ifeq ($(CC_MAJOR_VERSION),15)
RUST_CXXFLAGS=-include cstdint
endif
endif

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
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --release --lib -p agave-validator
cargo-solana: $(OBJDIR)/lib/libfdctl_version.a
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS) -L $(realpath $(OBJDIR)/lib) -l fdctl_version" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --release --bin solana
cargo-ledger-tool: $(OBJDIR)/lib/libfdctl_version.a
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS) -L $(realpath $(OBJDIR)/lib) -l fdctl_version" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --release --bin agave-ledger-tool
else ifeq ($(RUST_PROFILE),release-with-debug)
cargo-validator:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --profile=release-with-debug --lib -p agave-validator
cargo-solana: $(OBJDIR)/lib/libfdctl_version.a
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS) -L $(realpath $(OBJDIR)/lib) -l fdctl_version" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --profile=release-with-debug --bin solana
cargo-ledger-tool: $(OBJDIR)/lib/libfdctl_version.a
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS) -L $(realpath $(OBJDIR)/lib) -l fdctl_version" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --profile=release-with-debug --bin agave-ledger-tool
else
cargo-validator:
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS)" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --lib -p agave-validator
cargo-solana: $(OBJDIR)/lib/libfdctl_version.a
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS) -L $(realpath $(OBJDIR)/lib) -l fdctl_version" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --bin solana
cargo-ledger-tool: $(OBJDIR)/lib/libfdctl_version.a
	cd ./agave && env --unset=LDFLAGS RUSTFLAGS="$(RUSTFLAGS) -L $(realpath $(OBJDIR)/lib) -l fdctl_version" CXXFLAGS="$(RUST_CXXFLAGS)" ./cargo build --bin agave-ledger-tool
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

$(OBJDIR)/bin/solana: agave/target/$(RUST_PROFILE)/solana
	$(MKDIR) -p $(dir $@) && cp agave/target/$(RUST_PROFILE)/solana $@

solana: $(OBJDIR)/bin/solana

$(OBJDIR)/bin/agave-ledger-tool: agave/target/$(RUST_PROFILE)/agave-ledger-tool
	$(MKDIR) -p $(dir $@) && cp agave/target/$(RUST_PROFILE)/agave-ledger-tool $@

agave-ledger-tool: $(OBJDIR)/bin/agave-ledger-tool

endif
endif
endif
endif
endif
