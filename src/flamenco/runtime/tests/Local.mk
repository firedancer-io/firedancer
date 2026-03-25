ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_solfuzz.h)
$(call add-objs,fd_solfuzz fd_solfuzz_exec,fd_flamenco_test)

$(call add-hdrs,fd_dump_pb.h)
$(call add-objs,fd_dump_pb,fd_flamenco)
endif
endif

$(call add-hdrs,fd_instr_harness.h fd_txn_harness.h)
$(call add-objs,fd_elf_harness fd_instr_harness fd_txn_harness fd_harness_common fd_vm_harness,fd_flamenco_test)
ifdef FD_HAS_INT128
$(call add-objs,fd_block_harness,fd_flamenco_test)
endif
$(call add-objs,fd_sol_compat,fd_flamenco_test)

$(call add-hdrs,generated/context.pb.h generated/invoke.pb.h generated/txn.pb.h generated/block.pb.h generated/vm.pb.h generated/shred.pb.h generated/metadata.pb.h)
$(call add-objs,generated/context.pb generated/invoke.pb generated/txn.pb generated/block.pb generated/vm.pb generated/shred.pb generated/metadata.pb,fd_flamenco)

$(call add-hdrs,flatbuffers/generated/elf_builder.h,flatbuffers/generated/elf_reader.h)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
SOL_COMPAT_FLAGS:=-Wl,--undefined=fd_types_vt_by_name -Wl,--version-script=src/flamenco/runtime/tests/libfd_exec_sol_compat.map
$(call make-unit-test,test_sol_compat,test_sol_compat,fd_flamenco_test fd_flamenco fd_tango fd_funk fd_ballet fd_util fd_disco,$(FLATCC_LIBS))
$(call make-shared,libfd_exec_sol_compat.so,fd_sol_compat,fd_flamenco_test fd_flamenco fd_funk fd_ballet fd_util fd_disco,$(FLATCC_LIBS) $(SOL_COMPAT_FLAGS))
$(call make-unit-test,test_sol_compat_so,test_sol_compat_so,fd_util)
endif
endif

$(call add-hdrs,fd_svm_elfgen.h)
$(call add-objs,fd_svm_elfgen,fd_flamenco_test)
$(call make-unit-test,test_svm_elfgen,test_svm_elfgen,fd_flamenco_test fd_flamenco fd_ballet fd_util fd_disco)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_svm_mini.h)
$(call add-objs,fd_svm_mini,fd_flamenco_test)
$(call make-unit-test,test_svm_mini,test_svm_mini,fd_flamenco_test fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
$(call make-unit-test,test_accdb_svm,test_accdb_svm,fd_flamenco_test fd_flamenco fd_funk fd_tango fd_ballet fd_util fd_disco)
endif
endif

run-runtime-backtest: $(OBJDIR)/bin/firedancer-dev
	OBJDIR=$(OBJDIR) src/flamenco/runtime/tests/run_backtest_ci.sh $(BACKTEST_ARGS)
