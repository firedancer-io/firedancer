$(call add-hdrs,fd_exec_test.pb.h)
$(call add-objs,fd_exec_test.pb,fd_flamenco)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_exec_instr_test.h)
$(call add-objs,fd_exec_instr_test,fd_flamenco)

$(call make-unit-test,test_exec_instr,test_exec_instr,fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))
$(call make-shared,libfd_exec_sol_compat.so,fd_exec_sol_compat,fd_flamenco fd_funk fd_ballet fd_util,$(SECP256K1_LIBS))
endif

# TODO: add run-runtime-test-3 to the list of run-runtime-test after big merge is done
run-runtime-test: run-runtime-test-1 run-runtime-test-2 run-runtime-test-3

run-runtime-test-big: $(OBJDIR)/unit-test/test_native_programs $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l bad-incremental2 -s snapshot-262497545-3sFmKsyF32p4V2HMKaM6s2ymCG64NVcjuxYmen1aKky2.tar.zst  -i incremental-snapshot-262497545-262507921-Asuwpa3yuxsBZuVwsad41S3QHYejcdTdeNcqSHKbxvG1.tar.zst -p 250 -m 80000000 -e 255312010

run-runtime-native: $(OBJDIR)/unit-test/test_native_programs
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_native_tests.sh

run-runtime-test-1: $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -t 2 -X 1
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l helloworld -s snapshot-100-92rXQxDb3gbNU4YEjof4PjAQ9wDvqAXL4Ma3757kHPRs.tar.zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v118-multi
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l testnet-519 -s snapshot-255311992-Fju7xb3XaTY6SBxkGcsKko15EGAqnvdfkXBd1o6agPDq.tar.zst -p 64 -m 1000000 -e 255312010
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-251418170 -s snapshot-251418170-8sAkojR9PYTZvqiQZ1VWu27ewX5tXeVdC97wMXAtgHnT.tar.zst -p 64 -m 2000000 -e 251418233
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257066033 -s snapshot-257066033-AD2nFFTCtZVmo5nXLVsQMV1hiQDjzoEBXibRicBJc5Vw.tar.zst -p 16 -m 5000000 -e 257066038 --zst

#	src/flamenco/runtime/run_bpf_tests.sh

run-runtime-test-2: $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-254462437 -s snapshot-254462620-BEn8r5dNrKtaKo92pCXx2ZGrHm6cv6UrQ3ePmByEjj34.tar.zst -p 64 -m 20000000 -e 254462622 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-254462437 -s snapshot-254462437-9HqBi19BJJRZfHeBS3ZpkeP9B5SAxBxz6Kwug29yLHac.tar.zst -p 64 -m 20000000 -e 254463436 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-586 -s snapshot-253151900-HVhfam8TtRFVwFto5fWkhgR4mbBJmUxcnxeKZoW5MrSD.tar.zst  -p 64 -m 5000000 -e 253152100

run-runtime-test-3: $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257039990 -s snapshot-257039990-BSgErEc6ppN4p91meqPvUiXPiEhbakBNHMQQ4wKmceYv.tar.zst -p 64 -m 20000000 -e 257040010 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257037451 -s snapshot-257037451-36ERh35nFMRFB8sLHLTUnAd41TuzKYSTyxsa2bgBoMEj.tar.zst -p 16 -m 5000000 -e 257037545 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257035225 -s snapshot-257035225-EgwCNhhmffR38XWBXVp3GFs6fmtHKgzw5vEcD9e2oz14.tar.zst -p 32 -m 5000000 -e 257035233 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257465453 -s snapshot-257465452-3QExADnJwC756Law388ELX6xhtjnBGwToKVoQUFDcQfn.tar.zst -p 64 -m 80000000 -e 257485154 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257058865 -s snapshot-257058865-6SFEm7u5pLAhkm4vfiHiN3vMNkmZuyL2ACuaHznU52fi.tar.zst -p 16 -m 5000000 -e 257058870 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257059815 -s snapshot-257059815-AmWkVebTmg6ih2VTEjMmU9WtXhT3RygEoSJBHfDpyAG3.tar.zst -p 16 -m 5000000 -e 257059818 --zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-257061172 -s snapshot-257061172-8e6cUSMUx2VZZBDzwXjEY6bGkzPgnUmqrDyr4uErG8BF.tar.zst -p 16 -m 5000000 -e 257061175 --zst
