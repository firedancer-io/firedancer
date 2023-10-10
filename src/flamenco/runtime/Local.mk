# Unit test only works if there is an accessable rocksdb

ifneq ($(FD_HAS_ROCKSDB),)

$(call add-hdrs, \
  fd_banks_solana.h \
  fd_rocksdb.h \
	fd_executor.h \
	fd_acc_mgr.h \
	fd_hashes.h \
	fd_runtime.h \
	fd_rent_lists.h \
	fd_borrowed_account.h \
	fd_system_ids.h \
	fd_instr_info.h \
	fd_rawtxn.h \
	fd_pubkey_utils.h \
)

$(call add-hdrs,tests/fd_tests.h)

$(call add-objs, \
	fd_rocksdb \
	fd_executor \
	fd_acc_mgr \
	fd_hashes \
	fd_runtime \
	fd_rent_lists \
	fd_system_ids \
	fd_instr_info \
	fd_pubkey_utils \
	tests/fd_tests, \
	fd_flamenco \
)

$(call make-unit-test,test_runtime,test_runtime,fd_ballet fd_funk fd_util fd_flamenco)
$(call make-unit-test,test_sysvar_epoch_schedule,sysvar/test_sysvar_epoch_schedule,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_sysvar_rent,sysvar/test_sysvar_rent,fd_flamenco fd_funk fd_ballet fd_util)  # This should not depend on funk!
$(call make-unit-test,test_rent_lists,test_rent_lists,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-unit-test,test_bpf_loader_v4_program,program/test_bpf_loader_v4_program,fd_flamenco fd_funk fd_ballet fd_util)

$(call run-unit-test,test_sysvar_rent)

else

$(warning runtime disabled due to lack of rocksdb)

endif
