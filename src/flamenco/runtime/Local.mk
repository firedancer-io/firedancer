ifdef FD_HAS_INT128
$(call add-hdrs,fd_acc_mgr.h)
$(call add-objs,fd_acc_mgr,fd_flamenco)

$(call add-hdrs,fd_bank_hash_cmp.h fd_rwseq_lock.h)
$(call add-objs,fd_bank_hash_cmp,fd_flamenco)

$(call add-hdrs,fd_blockhashes.h)
$(call add-objs,fd_blockhashes,fd_flamenco)

$(call add-hdrs,fd_executor.h)
$(call add-objs,fd_executor,fd_flamenco)

$(call add-hdrs,fd_hashes.h)
$(call add-objs,fd_hashes,fd_flamenco)
$(call make-unit-test,test_hashes,test_hashes,fd_flamenco fd_funk fd_ballet fd_util)

$(call add-hdrs,fd_pubkey_utils.h)
$(call add-objs,fd_pubkey_utils,fd_flamenco)

$(call add-hdrs,fd_txncache.h)
$(call add-objs,fd_txncache,fd_flamenco)

$(call add-hdrs,fd_cost_tracker.h)
$(call add-objs,fd_cost_tracker,fd_flamenco)
$(call make-unit-test,test_cost_tracker,test_cost_tracker,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_cost_tracker,)

$(call add-hdrs,fd_compute_budget_details.h)
$(call add-objs,fd_compute_budget_details,fd_flamenco)

$(call add-hdrs,fd_borrowed_account.h)
$(call add-objs,fd_borrowed_account,fd_flamenco)

$(call add-hdrs, tests/fd_dump_pb.h)
$(call add-objs, tests/fd_dump_pb,fd_flamenco)

$(call add-hdrs,fd_txn_account.h)
$(call add-objs,fd_txn_account,fd_flamenco)
$(call make-unit-test,test_txn_account,test_txn_account,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_txn_account,)

$(call add-hdrs,fd_bank.h)
$(call add-objs,fd_bank,fd_flamenco)
$(call make-unit-test,test_bank,test_bank,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_bank,)

$(call make-unit-test,test_txncache,test_txncache,fd_flamenco fd_ballet fd_util)

ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_txn_rw_conflicts,test_txn_rw_conflicts,fd_flamenco fd_funk fd_ballet fd_util, $(SECP256K1_LIBS))
$(call run-unit-test,test_txn_rw_conflicts)
endif

ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_runtime.h fd_runtime_init.h fd_runtime_err.h fd_runtime_const.h)
$(call add-objs,fd_runtime fd_runtime_init ,fd_flamenco)
endif

$(call add-hdrs,fd_svm_account.h)
$(call make-unit-test,test_svm_account,test_svm_account,fd_flamenco fd_funk fd_ballet fd_util)

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
endif
endif
