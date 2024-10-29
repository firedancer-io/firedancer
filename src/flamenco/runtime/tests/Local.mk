$(call add-hdrs,generated/context.pb.h,generated/elf.pb.h,generated/invoke.pb.h,generated/txn.pb.h,generated/block.pb.h,generated/vm.pb.h,generated/shred.pb.h generated/metadata.pb.h generated/pack.pb.h)
$(call add-objs,generated/context.pb generated/elf.pb generated/invoke.pb generated/txn.pb generated/block.pb generated/vm.pb generated/shred.pb generated/metadata.pb generated/pack.pb,fd_flamenco)

ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
$(call add-hdrs,fd_exec_instr_test.h fd_vm_test.h fd_pack_test.h)
$(call add-objs,fd_exec_instr_test fd_vm_test fd_pack_test,fd_flamenco)
$(call add-objs,fd_exec_sol_compat,fd_flamenco)

$(call make-unit-test,test_exec_sol_compat,test_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))
$(call make-shared,libfd_exec_sol_compat.so,fd_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))

ifdef FD_HAS_FUZZ_STUBS
# The --wrap flag stubs out a function so that we can replace it with our own implementation in the fuzz harness(es)
# See __wrap_fd_execute_instr in  fd_exec_instr_test.c for example
# We guard this with FD_HAS_FUZZ_STUBS because the --wrap flag may not be portable across linkers
WRAP_FLAGS += -Xlinker --wrap=fd_execute_instr
$(call make-shared,libfd_exec_sol_compat_stubbed.so,fd_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS) $(WRAP_FLAGS))
$(call make-unit-test,test_exec_sol_compat_stubbed,test_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS) $(WRAP_FLAGS))
endif

endif
endif

run-runtime-test: $(OBJDIR)/bin/fd_ledger
	python3.11 ./src/flamenco/runtime/tests/run_ledger_tests_all.py ./src/flamenco/runtime/tests/run_ledger_tests_all.txt

run-runtime-test-nightly: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l mainnet-257033306 -s snapshot-257033306-EE3WdRoE4J1LTjegJMK3ZzxKZbSMQhLMaTM5Jp4SygMU.tar.zst -p 100 -y 450 -m 500000000 -e 257213306 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l mainnet-296243940 -s snapshot-296400651-HDt9Gf1YKcruvuBV4q442qV4xjHer4KZ9sZao9XQspZP.tar.zst -p 75 -y 750 -m 700000000 -e 296550651 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l devnet-340941576 -s snapshot-340924320-8j9h6EKmuZ3G93Y3Pb3FqrNdCDTGE5PKowHMY3xkXG1K.tar.zst -p 75 -y 400 -m 200000000 -e 340941580 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l testnet-305516256 -s snapshot-305516254-C4oM7ajmCMo1aDakR8Q8FriSVpXW53jwbb3da37jm7bN.tar.zst -p 75 -y 400 -m 150000000 -e 305516292 --zst
