# Unit test only works if there is an accessable rocksdb

ifneq ($(FD_HAS_ROCKSDB),)

$(call make-lib,fd_sol_tests)
$(call add-objs,$(patsubst src/flamenco/runtime/tests/%.c,%,$(wildcard src/flamenco/runtime/tests/generated/*.c)),fd_sol_tests)

$(call make-unit-test,test_native_programs,test_native_programs,fd_ballet fd_funk fd_util fd_sol_tests fd_flamenco)
$(call make-unit-test,test_sign_programs,test_sign_programs fd_tests,fd_ballet fd_funk fd_util fd_flamenco)

run-runtime-test: $(OBJDIR)/unit-test/test_native_programs $(OBJDIR)/unit-test/test_runtime $(OBJDIR)/bin/fd_frank_ledger
	OBJDIR=$(OBJDIR) src/flamenco/runtime/run_ledger_tests.sh
#	src/flamenco/runtime/run_bpf_tests.sh

endif
