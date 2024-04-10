# Unit test only works if there is an accessable rocksdb

ifdef FD_HAS_ROCKSDB

$(call make-lib,fd_sol_tests)
$(call add-objs,$(patsubst src/flamenco/runtime/tests/%.c,%,$(wildcard src/flamenco/runtime/tests/generated/*.c)),fd_sol_tests)

$(call make-unit-test,test_native_programs,test_native_programs fd_tests,fd_ballet fd_funk fd_util fd_sol_tests fd_flamenco)
$(call run-unit-test,test_native_programs)
$(call make-unit-test,test_sign_programs,test_sign_programs fd_tests,fd_ballet fd_funk fd_util fd_flamenco)
$(call make-unit-test,test_rent_lists,test_rent_lists,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_hashes,test_hashes,fd_ballet fd_funk fd_util fd_flamenco)
$(call make-unit-test,bench_tps,bench_tps,fd_aio fd_quic fd_tls fd_ballet fd_tango fd_util)

run-runtime-test: run-runtime-test-1 run-runtime-test-2

run-runtime-test-big: $(OBJDIR)/unit-test/test_native_programs $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l bad-incremental2 -s snapshot-262497545-3sFmKsyF32p4V2HMKaM6s2ymCG64NVcjuxYmen1aKky2.tar.zst  -i incremental-snapshot-262497545-262507921-Asuwpa3yuxsBZuVwsad41S3QHYejcdTdeNcqSHKbxvG1.tar.zst -p 250 -m 80000000 -e 255312010

run-runtime-test-1: $(OBJDIR)/unit-test/test_native_programs $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -t 2 -X 1
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l helloworld -s snapshot-100-92rXQxDb3gbNU4YEjof4PjAQ9wDvqAXL4Ma3757kHPRs.tar.zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v118-multi
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l testnet-519 -s snapshot-255311992-Fju7xb3XaTY6SBxkGcsKko15EGAqnvdfkXBd1o6agPDq.tar.zst -p 64 -m 1000000 -e 255312010
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-251418170 -s snapshot-251418170-8sAkojR9PYTZvqiQZ1VWu27ewX5tXeVdC97wMXAtgHnT.tar.zst -p 64 -m 2000000 -e 251418233
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_native_tests.sh
#	src/flamenco/runtime/run_bpf_tests.sh

run-runtime-test-2: $(OBJDIR)/unit-test/test_native_programs $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-254462437 -s snapshot-254462620-BEn8r5dNrKtaKo92pCXx2ZGrHm6cv6UrQ3ePmByEjj34.tar.zst -p 64 -m 20000000 -e 254462622 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-254462437 -s snapshot-254462437-9HqBi19BJJRZfHeBS3ZpkeP9B5SAxBxz6Kwug29yLHac.tar.zst -p 64 -m 20000000 -e 254463436 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-586 -s snapshot-253151900-HVhfam8TtRFVwFto5fWkhgR4mbBJmUxcnxeKZoW5MrSD.tar.zst  -p 64 -m 5000000 -e 253152100
endif

# New executor tests

$(call add-hdrs,fd_exec_test.pb.h)
$(call add-objs,fd_exec_test.pb,fd_flamenco)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_exec_instr_test.h)
$(call add-objs,fd_exec_instr_test,fd_flamenco)

$(call make-unit-test,test_exec_instr,test_exec_instr,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-shared,libfd_exec_sol_compat.so,fd_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util)
endif
