ifdef FD_HAS_INT128
$(call add-objs,fd_shred_dest,fd_disco)
$(call add-objs,fd_shredder,fd_disco)
$(call add-objs,fd_shred_cap,fd_disco,fd_flamenco)
$(call add-objs,fd_fec_resolver,fd_disco)
$(call add-objs,fd_stake_ci,fd_disco)
$(call make-unit-test,test_shred_dest,test_shred_dest,fd_disco fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_fec_resolver,test_fec_resolver,fd_flamenco fd_disco fd_ballet fd_util fd_tango fd_reedsol)
$(call make-unit-test,test_stake_ci,test_stake_ci,fd_disco fd_flamenco fd_ballet fd_util fd_tango fd_reedsol)
$(call run-unit-test,test_shred_dest,)
$(call run-unit-test,test_fec_resolver,)
$(call run-unit-test,test_stake_ci,)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_shredder,test_shredder,fd_disco fd_flamenco fd_ballet fd_util fd_reedsol)
$(call run-unit-test,test_shredder,)
$(call make-fuzz-test,fuzz_shred_sanitize,fuzz_shred_sanitize,fd_ballet fd_util solana_ledger)

# Just manually run ./cargo build --profile=release-with-debug --lib -p solana-ledger
$(OBJDIR)/lib/libsolana_ledger.a: agave/target/$(RUST_PROFILE)/libsolana_ledger.a
	$(MKDIR) $(dir $@) && cp agave/target/$(RUST_PROFILE)/libsolana_ledger.a $@
endif
endif
