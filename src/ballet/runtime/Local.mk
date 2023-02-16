# Unit test only works if there is an accessable rocksdb

ifdef FD_HAS_ROCKSDB

$(call add-hdrs,fd_banks_solana.h fd_global_state.h fd_rocksdb.h)
$(call add-objs,fd_banks_solana fd_rocksdb,fd_ballet)

$(call make-unit-test,test_rocksdb,test_rocksdb fd_rocksdb,fd_ballet fd_util)

endif

