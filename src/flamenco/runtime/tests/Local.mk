ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1

$(call add-hdrs,fd_solfuzz.h)
$(call add-objs,fd_solfuzz fd_solfuzz_exec,fd_flamenco_test)

$(call add-hdrs,fd_instr_harness.h fd_txn_harness.h)
$(call add-objs,fd_elf_harness fd_instr_harness fd_txn_harness fd_block_harness fd_harness_common fd_vm_harness fd_types_harness,fd_flamenco_test)
$(call add-objs,fd_sol_compat,fd_flamenco_test)

$(call add-hdrs,generated/context.pb.h,generated/elf.pb.h,generated/invoke.pb.h,generated/txn.pb.h,generated/block.pb.h,generated/vm.pb.h,generated/type.pb.h,generated/shred.pb.h generated/metadata.pb.h)
$(call add-objs,generated/context.pb generated/elf.pb generated/invoke.pb generated/txn.pb generated/block.pb generated/vm.pb generated/type.pb generated/shred.pb generated/metadata.pb,fd_flamenco)

SOL_COMPAT_FLAGS:=-Wl,--undefined=fd_types_vt_by_name -Wl,--version-script=src/flamenco/runtime/tests/libfd_exec_sol_compat.map
$(call make-unit-test,test_sol_compat,test_sol_compat,fd_flamenco_test fd_flamenco fd_tango fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))
$(call make-shared,libfd_exec_sol_compat.so,fd_sol_compat,fd_flamenco_test fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS) $(SOL_COMPAT_FLAGS))
$(call make-unit-test,test_sol_compat_so,test_sol_compat_so,fd_util)

run-runtime-backtest: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_backtest_ci.sh

endif
endif

