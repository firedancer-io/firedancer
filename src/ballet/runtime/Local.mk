# Unit test only works if there is an accessable rocksdb

ifneq (,/home/jsiegel/repos/solana/test-ledger/rocksdb)
ifeq ($(FD_HAS_ROCKSDB),1)
$(call make-unit-test,test_rocksdb,test_rocksdb fd_rocksdb,fd_ballet fd_util)
endif
endif

