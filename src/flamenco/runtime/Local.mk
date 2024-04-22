# Unit test only works if there is an accessable rocksdb

ifdef FD_HAS_ROCKSDB

$(call add-hdrs, \
  fd_rocksdb.h \
	fd_hashes.h \
	fd_pubkey_utils.h \
	fd_blockstore.h \
	fd_snapshot_loader.h \
	fd_bank_hash_cmp.h \
)

$(call add-hdrs,tests/fd_tests.h)

$(call add-objs,fd_rocksdb,fd_flamenco)
$(call add-objs,fd_hashes,fd_flamenco)
$(call add-objs,fd_runtime,fd_flamenco)
$(call add-objs,fd_pubkey_utils,fd_flamenco)
$(call add-objs,fd_blockstore,fd_flamenco)
$(call add-objs,fd_snapshot_loader,fd_flamenco)
$(call add-objs,fd_bank_hash_cmp,fd_flamenco)

$(call make-unit-test,test_blockstore,test_blockstore,fd_flamenco fd_funk fd_ballet fd_util)

$(call run-unit-test,test_sysvar_rent)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_account.h)
$(call add-objs,fd_account,fd_flamenco)

$(call add-hdrs,fd_runtime.h)
$(call add-hdrs,fd_rent_lists.h)

$(call add-hdrs,fd_executor.h)
$(call add-objs,fd_executor,fd_flamenco)

$(call add-hdrs,fd_acc_mgr.h)
$(call add-objs,fd_acc_mgr,fd_flamenco)
$(call make-unit-test,test_acc_mgr,test_acc_mgr,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_acc_mgr)

$(call add-hdrs,fd_borrowed_account.h)
$(call add-objs,fd_borrowed_account,fd_flamenco)
endif

else
$(warning runtime disabled due to lack of rocksdb)
endif

$(call add-hdrs,fd_system_ids.h)
$(call add-objs,fd_system_ids,fd_flamenco)
$(call make-unit-test,test_system_ids,test_system_ids,fd_flamenco fd_util fd_ballet)
$(call run-unit-test,test_system_ids,)
