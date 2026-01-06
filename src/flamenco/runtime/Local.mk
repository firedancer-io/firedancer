$(call add-hdrs,fd_acc_mgr.h)
$(call add-objs,fd_acc_mgr,fd_flamenco)

$(call add-hdrs,fd_blockhashes.h)
$(call add-objs,fd_blockhashes,fd_flamenco)

$(call add-objs,fd_core_bpf_migration,fd_flamenco)

$(call add-hdrs,fd_executor.h)
ifdef FD_HAS_INT128
$(call add-objs,fd_executor,fd_flamenco)
endif

$(call add-hdrs,fd_hashes.h)
$(call add-objs,fd_hashes,fd_flamenco)
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_hashes,test_hashes,fd_flamenco fd_funk fd_ballet fd_util)
endif

$(call add-hdrs,fd_pubkey_utils.h)
$(call add-objs,fd_pubkey_utils,fd_flamenco)

ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_txncache_shmem.h fd_txncache.h)
$(call add-objs,fd_txncache_shmem fd_txncache,fd_flamenco)
endif

$(call add-hdrs,fd_cost_tracker.h)
$(call add-objs,fd_cost_tracker,fd_flamenco)
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_cost_tracker,test_cost_tracker,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_cost_tracker,)
endif

$(call add-hdrs,fd_compute_budget_details.h)
$(call add-objs,fd_compute_budget_details,fd_flamenco)

$(call add-hdrs,fd_borrowed_account.h)
$(call add-objs,fd_borrowed_account,fd_flamenco)

$(call add-hdrs,fd_acc_pool.h)
$(call add-objs,fd_acc_pool,fd_flamenco)

$(call add-hdrs,fd_genesis_parse.h)
$(call add-objs,fd_genesis_parse,fd_flamenco)

$(call add-hdrs,fd_txn_account.h)
$(call add-objs,fd_txn_account,fd_flamenco)
ifdef FD_HAS_INT128
$(call make-unit-test,test_txn_account,test_txn_account,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_txn_account,)
endif

ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_runtime_alut,test_runtime_alut,fd_flamenco fd_funk fd_ballet fd_util)
endif

ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_bank.h)
$(call add-objs,fd_bank,fd_flamenco)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_bank,test_bank,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_bank,)
$(call make-unit-test,test_static_instruction_limit,test_static_instruction_limit,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_static_instruction_limit,)
endif
endif
endif

ifdef FD_HAS_ALLOCA
$(call make-unit-test,test_txncache,test_txncache,fd_flamenco fd_ballet fd_util)
endif

ifdef FD_HAS_ATOMIC
ifdef FD_HAS_INT128
$(call add-hdrs,fd_runtime.h fd_runtime_err.h fd_runtime_const.h fd_runtime_stack.h fd_runtime_helpers.h)
$(call add-objs,fd_runtime,fd_flamenco)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_deprecate_rent_exemption_threshold,test_deprecate_rent_exemption_threshold,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_deprecate_rent_exemption_threshold,)
$(call make-unit-test,test_instr_acct_bounds,test_instr_acct_bounds,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_instr_acct_bounds,)
endif
endif
endif
endif

$(call add-hdrs,fd_system_ids.h)
$(call add-objs,fd_system_ids,fd_flamenco)
$(call make-unit-test,test_system_ids,test_system_ids,fd_flamenco fd_util fd_ballet)
$(call run-unit-test,test_system_ids,)

ifdef FD_HAS_ROCKSDB
$(call add-hdrs,fd_rocksdb.h)
$(call add-objs,fd_rocksdb,fd_flamenco)
endif

ifdef FD_HAS_ATOMIC

ifdef FD_HAS_HOSTED
#$(call make-unit-test,test_archive_block,test_archive_block, fd_flamenco fd_util fd_ballet,$(SECP256K1_LIBS))
# TODO: Flakes
# $(call run-unit-test,test_txncache,)
$(call make-fuzz-test,fuzz_genesis_parse,fuzz_genesis_parse,fd_flamenco fd_ballet fd_util)
endif
endif
