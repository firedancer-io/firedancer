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

# WARNING 03-07 16:26:44.035818 569410 f0   0    src/flamenco/runtime/fd_runtime.c(3593): Bank hash mismatch! slot=251418232 expected=H44FqPbX6Q9ZWKjzQppz8tEdQnKxkbFQms7VA2ZWE4sN, got=matVdNPdYycwL3PJ5zB7bHKQv2zuv43SH8fAz9xwKP5

run-runtime-test: $(OBJDIR)/unit-test/test_native_programs $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
#	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-251418170 -s snapshot-251418231-EkDdaUmskEdPnTtooQMUaFY8tNPBAqy5dDf8HyqiatLe.tar.zst -p 64 -m 2000000 -e 251418233
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -t 2 -X 1
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l helloworld -s snapshot-100-92rXQxDb3gbNU4YEjof4PjAQ9wDvqAXL4Ma3757kHPRs.tar.zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v118-multi
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-579 -s snapshot-250127990-2qrtKDgYDP7xSzT4LkVDVfDTb42JHyn7b6L88kwaiL9E.tar.zst -p 64 -m 5000000 -e 250128010
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l testnet-519 -s snapshot-255311992-Fju7xb3XaTY6SBxkGcsKko15EGAqnvdfkXBd1o6agPDq.tar.zst -p 64 -m 1000000 -e 255312010
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l mainnet-251418170 -s snapshot-251418170-8sAkojR9PYTZvqiQZ1VWu27ewX5tXeVdC97wMXAtgHnT.tar.zst -p 64 -m 2000000 -e 251418231
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_native_tests.sh
#	src/flamenco/runtime/run_bpf_tests.sh

endif

# New executor tests

$(call add-hdrs,fd_exec_test.pb.h)
$(call add-objs,fd_exec_test.pb,fd_flamenco)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_exec_instr_test.h)
$(call add-objs,fd_exec_instr_test,fd_flamenco)

$(call make-unit-test,test_exec_instr,test_exec_instr,fd_flamenco fd_funk fd_ballet fd_util)
endif
