# Unit test only works if there is an accessable rocksdb

ifneq ($(FD_HAS_ROCKSDB),)

$(call add-hdrs, \
  fd_banks_solana.h \
  fd_rocksdb.h \
	fd_executor.h \
	fd_acc_mgr.h \
	fd_hashes.h \
	fd_runtime.h \
	fd_replay.h \
	fd_borrowed_account.h \
	fd_system_ids.h \
	fd_rawtxn.h \
	fd_pubkey_utils.h \
	fd_fork_mgr.h \
	fd_blockstore.h \
	fd_snapshot_loader.h \
	fd_tvu.h \
)

$(call add-hdrs,tests/fd_tests.h)

$(call add-objs, \
	fd_rocksdb \
	fd_executor \
	fd_acc_mgr \
	fd_hashes \
	fd_runtime \
	fd_replay \
	fd_system_ids \
	fd_pubkey_utils \
	fd_fork_mgr \
	fd_borrowed_account \
	fd_blockstore \
	fd_snapshot_loader \
	fd_tvu \
	tests/fd_tests \
	, \
	fd_flamenco \
)

$(call make-unit-test,test_runtime,test_runtime,fd_ballet fd_funk fd_util fd_flamenco)
$(call make-unit-test,test_sysvar_epoch_schedule,sysvar/test_sysvar_epoch_schedule,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_sysvar_rent,sysvar/test_sysvar_rent,fd_flamenco fd_funk fd_ballet fd_util)  # This should not depend on funk!
$(call make-unit-test,test_bpf_loader_v4_program,program/test_bpf_loader_v4_program,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_blockstore,test_blockstore,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_tvu,test_tvu,fd_flamenco fd_funk fd_ballet fd_util fd_tango)

$(call run-unit-test,test_sysvar_rent)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_rent_lists.h)
endif

else
$(warning runtime disabled due to lack of rocksdb)
endif
