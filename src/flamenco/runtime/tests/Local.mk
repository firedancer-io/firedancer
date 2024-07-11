$(call add-hdrs,generated/context.pb.h,generated/elf.pb.h,generated/invoke.pb.h,generated/txn.pb.h,generated/vm.pb.h)
$(call add-objs,generated/context.pb generated/elf.pb generated/invoke.pb generated/txn.pb generated/vm.pb,fd_flamenco)

WRAP_FLAGS += -Xlinker --wrap=fd_vm_cpi_execute_instr
ifdef FD_HAS_INT128
ifdef FD_HAS_SECP256K1
$(call add-hdrs,fd_exec_instr_test.h fd_vm_validate_test.h)
$(call add-objs,fd_exec_instr_test fd_vm_validate_test,fd_flamenco)
$(call add-objs,fd_exec_sol_compat,fd_flamenco)

$(call make-unit-test,test_exec_instr,test_exec_instr,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS))
$(call make-unit-test,test_exec_sol_compat,test_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS) $(WRAP_FLAGS))
$(call make-shared,libfd_exec_sol_compat.so,fd_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(SECP256K1_LIBS) $(WRAP_FLAGS))
endif
endif

run-runtime-test: $(OBJDIR)/bin/fd_ledger
	python3.11 ./src/flamenco/runtime/tests/run_ledger_tests_all.py ./src/flamenco/runtime/tests/run_ledger_tests_all.txt

run-runtime-test-nightly: $(OBJDIR)/bin/fd_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_nightly_test.sh -l mainnet-257033306 -s snapshot-257033306-EE3WdRoE4J1LTjegJMK3ZzxKZbSMQhLMaTM5Jp4SygMU.tar.zst -p 100 -y 450 -m 500000000 -e 257213306 --zst
