# Unit test only works if there is an accessable rocksdb

ifneq ($(ROCKSDB),)

$(call add-hdrs,fd_banks_solana.h fd_global_state.h fd_rocksdb.h)
$(call add-objs,fd_banks_solana fd_rocksdb fd_funk_stub,fd_ballet)

$(call make-unit-test,test_runtime,test_runtime,fd_ballet fd_util)

else

$(warning runtime disabled due to lack of rocksdb)

endif

