# Unit test only works if there is an accessable rocksdb

ifneq ($(FD_HAS_ROCKSDB),)

$(call make-unit-test,test_native_programs,test_native_programs,fd_ballet fd_funk fd_util fd_tests fd_flamenco)

endif
