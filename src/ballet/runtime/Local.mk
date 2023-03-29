# Unit test only works if there is an accessable rocksdb

ifneq ($(FD_HAS_ROCKSDB),)

$(call add-hdrs,fd_banks_solana.h fd_global_state.h fd_rocksdb.h fd_executor.h fd_acc_mgr.h program/fd_system_program.h program/fd_vote_program.h fd_hashes.h fd_types.h)
$(call add-objs,fd_banks_solana fd_rocksdb fd_executor fd_acc_mgr program/fd_system_program program/fd_vote_program fd_hashes fd_types,fd_ballet)

$(call make-unit-test,test_runtime,test_runtime,fd_ballet fd_funk fd_util)

else

$(warning runtime disabled due to lack of rocksdb)

endif
