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

run-backtest-test: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_backtest_ci.sh

run-runtime-test-nightly: $(OBJDIR)/bin/fd_ledger
	# OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l mainnet-257033306 -s snapshot-257033306-EE3WdRoE4J1LTjegJMK3ZzxKZbSMQhLMaTM5Jp4SygMU.tar.zst -p 100 -y 450 -m 500000000 -e 257213306 -c 2.0.0
	# OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l mainnet-296243940 -s snapshot-296400651-HDt9Gf1YKcruvuBV4q442qV4xjHer4KZ9sZao9XQspZP.tar.zst -p 100 -y 750 -m 700000000 -e 296550651 -c 2.0.0
	# OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l devnet-340941576  -s snapshot-340924320-8j9h6EKmuZ3G93Y3Pb3FqrNdCDTGE5PKowHMY3xkXG1K.tar.zst -p 100 -y 400 -m 200000000 -e 340941580 -c 2.0.0
	# OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l testnet-305516256 -s snapshot-305516254-C4oM7ajmCMo1aDakR8Q8FriSVpXW53jwbb3da37jm7bN.tar.zst -p 100 -y 400 -m 150000000 -e 305516292 -c 2.0.0
	# OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l devnet-346032000  -s snapshot-346031900-2EyfK3LCFoA69PPJ9JBPNDXV9ShDMLok7Vo6sr8LfdFc.tar.zst -p 100 -y 400 -m 200000000 -e 346032005 -c 2.0.15
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l mainnet-327443157  -s snapshot-327493391-9z5sYZhTCUbMKvXKotuCqN1y5TTt9T4PpxJzE6FLoQiz.tar.zst -p 100 -y 750 -m 950000000 -e 327593391 -c 2.1.11


run-runtime-test-nightly-asan: $(OBJDIR)/bin/fd_ledger
	# OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l v201-small        -s snapshot-100-38CM8ita1fT5SmSLUEeqQZffn2xsy9vKz3WJmsFSnhrJ.tar.zst       -p 100 -y 16  -m 500000    -e 120       -c 2.0.1
	# OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l devnet-330914784  -s snapshot-330914783-BujhdWiXTfRPfFYMG3GZdEcNc18KyvCcAq9QL9e1i1Fk.tar.zst -p 100 -y 16  -m 500000    -e 330914785 -c 2.0.8
