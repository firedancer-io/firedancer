ifdef FD_HAS_HOSTED
ifdef FD_HAS_ROCKSDB
$(call make-bin,fd_blockstore2shredcap,fd_blockstore2shredcap fd_rocksdb_src,fd_discof fd_flamenco fd_ballet fd_util,$(ROCKSDB_LIBS))
endif
endif
