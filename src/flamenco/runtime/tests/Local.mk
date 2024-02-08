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

run-runtime-test: $(OBJDIR)/unit-test/test_native_programs $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l empty-ledger -t 2 -X 133
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l empty-ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_snapshot_tests.sh -l v1181-snap -s snapshot-100-2YC8ZW7NtJNgEphk3jB9BmcQKHSnUv8YGp2tUfQSodBR.tar.zst -i incremental-snapshot-100-150-GcNxXtNgzsNHASLJAfJ9eMN2VZKM9VtJKvT9bUveqzda.tar.zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_snapshot_tests.sh -l v1181-snap -s snapshot-100-2YC8ZW7NtJNgEphk3jB9BmcQKHSnUv8YGp2tUfQSodBR.tar.zst
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v17-big
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v11712-test-ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_ledger_tests.sh -l v17-multi -s snapshot-800-3vyLp4DbPnomGAqcxZcBfm58bbZh25EGrkTvF9PvoVc2.tar.zst
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
