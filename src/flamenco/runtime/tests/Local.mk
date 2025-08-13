$(call add-hdrs,harness/generated/context.pb.h,harness/generated/elf.pb.h,harness/generated/invoke.pb.h,harness/generated/txn.pb.h,harness/generated/block.pb.h,harness/generated/vm.pb.h,harness/generated/type.pb.h,harness/generated/shred.pb.h harness/generated/metadata.pb.h)
$(call add-objs,harness/generated/context.pb harness/generated/elf.pb harness/generated/invoke.pb harness/generated/txn.pb harness/generated/block.pb harness/generated/vm.pb harness/generated/type.pb harness/generated/shred.pb harness/generated/metadata.pb,fd_flamenco)

ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
$(call add-hdrs,harness/fd_elf_harness.h harness/fd_instr_harness.h harness/fd_txn_harness.h harness/fd_block_harness.h harness/fd_harness_common.h harness/fd_vm_harness.h harness/fd_types_harness.h)
$(call add-objs,harness/fd_elf_harness harness/fd_instr_harness harness/fd_txn_harness harness/fd_block_harness harness/fd_harness_common harness/fd_vm_harness harness/fd_types_harness,fd_flamenco_test)
$(call add-objs,harness/fd_exec_sol_compat,fd_flamenco_test)

SOL_COMPAT_FLAGS:=-Wl,--undefined=fd_types_vt_by_name
$(call make-unit-test,test_exec_sol_compat,test_exec_sol_compat,fd_flamenco_test fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))
$(call make-shared,libfd_exec_sol_compat.so,harness/fd_exec_sol_compat,fd_flamenco_test fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS) $(SOL_COMPAT_FLAGS))

endif
endif

run-runtime-backtest: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_backtest_ci.sh
