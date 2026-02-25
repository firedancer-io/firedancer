$(call add-hdrs,fd_gossip.h fd_gossip_message.h fd_gossip_out.h fd_gossip_txbuild.h fd_gossip_purged.h)
ifdef FD_HAS_ALLOCA
$(call add-objs,fd_gossip fd_gossip_message fd_gossip_out fd_gossip_txbuild fd_gossip_purged,fd_flamenco)
endif

$(call add-hdrs,fd_bloom.h fd_gossip_wsample.h)
$(call add-objs,fd_bloom fd_active_set fd_ping_tracker fd_gossip_wsample,fd_flamenco)

$(call make-unit-test,test_bloom,test_bloom,fd_flamenco fd_util)
$(call run-unit-test,test_bloom)

$(call make-unit-test,test_active_set,test_active_set,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_active_set)

$(call make-unit-test,test_ping_tracker,test_ping_tracker,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_ping_tracker)

$(call make-unit-test,test_gossip_wsample,test_gossip_wsample,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_gossip_wsample)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_gossip_message_serialize,fuzz_gossip_message_serialize,fd_flamenco fd_ballet fd_util)
endif

# TODO: This is a differential fuzzer that compares the output of the C
# implementation to the Rust implementation.  It requires a small shim
# to the Rust side to work, since Agave does not expose the gossip
# deserializer well enough by default.
#
# See: differential_fuzzer.patch for the diff which is needed on the
# Agave side for this to work properly.
#
# ifdef FD_HAS_HOSTED
# $(call make-fuzz-test,fuzz_gossip_message_deserialize,fuzz_gossip_message_deserialize,fd_flamenco fd_ballet fd_util solana_gossip,-lstdc++ -lpthread)
# $(call make-unit-test,bench_gossip_message_deserialize,bench_gossip_message_deserialize,fd_flamenco fd_ballet fd_util solana_gossip,-lstdc++ -lpthread)
# endif

GOSSIP_FUZZ_RUSTFLAGS:=
ifdef FD_HAS_FUZZ
GOSSIP_FUZZ_RUSTFLAGS+=-Cpasses=sancov-module
GOSSIP_FUZZ_RUSTFLAGS+=-Cllvm-args=-sanitizer-coverage-inline-8bit-counters
GOSSIP_FUZZ_RUSTFLAGS+=-Cllvm-args=-sanitizer-coverage-level=4
GOSSIP_FUZZ_RUSTFLAGS+=-Cllvm-args=-sanitizer-coverage-pc-table
endif
GOSSIP_FUZZ_RUSTFLAGS+=-Clink-dead-code
GOSSIP_FUZZ_RUSTFLAGS+=-Cforce-frame-pointers=yes
GOSSIP_FUZZ_RUSTFLAGS+=-Awarnings

GOSSIP_FUZZ_RUST_VERSION:=1.86.0

.PHONY: gossip-fuzz-rustlib

gossip-fuzz-rustlib:
	cd agave && RUSTFLAGS="$(GOSSIP_FUZZ_RUSTFLAGS)" cargo +$(GOSSIP_FUZZ_RUST_VERSION) build -p solana-gossip --lib --target x86_64-unknown-linux-gnu --release

agave/target/x86_64-unknown-linux-gnu/release/libsolana_gossip.a: gossip-fuzz-rustlib

$(OBJDIR)/lib/libsolana_gossip.a: agave/target/x86_64-unknown-linux-gnu/release/libsolana_gossip.a
	$(MKDIR) $(dir $@) && cp $< $@
