$(call add-hdrs,harness/generated/context.pb.h,harness/generated/elf.pb.h,harness/generated/invoke.pb.h,harness/generated/txn.pb.h,harness/generated/block.pb.h,harness/generated/vm.pb.h,harness/generated/type.pb.h,harness/generated/shred.pb.h harness/generated/metadata.pb.h harness/generated/pack.pb.h)
$(call add-objs,harness/generated/context.pb harness/generated/elf.pb harness/generated/invoke.pb harness/generated/txn.pb harness/generated/block.pb harness/generated/vm.pb harness/generated/type.pb harness/generated/shred.pb harness/generated/metadata.pb harness/generated/pack.pb,fd_flamenco)

ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
$(call add-hdrs,harness/fd_elf_harness.h harness/fd_instr_harness.h harness/fd_txn_harness.h harness/fd_block_harness.h harness/fd_harness_common.h harness/fd_vm_harness.h harness/fd_pack_harness.h harness/fd_types_harness.h)
$(call add-objs,harness/fd_elf_harness harness/fd_instr_harness harness/fd_txn_harness harness/fd_block_harness harness/fd_harness_common harness/fd_vm_harness harness/fd_pack_harness harness/fd_types_harness,fd_flamenco_test)
$(call add-objs,harness/fd_exec_sol_compat,fd_flamenco_test)

SOL_COMPAT_FLAGS:=-Wl,--undefined=fd_types_vt_by_name
$(call make-unit-test,test_exec_sol_compat,test_exec_sol_compat,fd_flamenco_test fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))
$(call make-shared,libfd_exec_sol_compat.so,harness/fd_exec_sol_compat,fd_flamenco_test fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS) $(SOL_COMPAT_FLAGS))

endif
endif

run-runtime-test: $(OBJDIR)/bin/fd_ledger
	python3.11 ./src/flamenco/runtime/tests/run_ledger_tests_all.py ./src/flamenco/runtime/tests/run_ledger_tests_all.txt

run-runtime-backtest: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_backtest_ci.sh

run-runtime-test-nightly: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l mainnet-327443157  -s snapshot-327493391-9z5sYZhTCUbMKvXKotuCqN1y5TTt9T4PpxJzE6FLoQiz.tar.zst -p 100 -y 750 -m 950000000 -e 327593391 -c 2.1.11

run-runtime-backtest-nightly: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_backtest.sh -l mainnet-327443157  -s snapshot-327493391-9z5sYZhTCUbMKvXKotuCqN1y5TTt9T4PpxJzE6FLoQiz.tar.zst -y 750 -m 950000000 -e 327593391 -c 2.1.11
