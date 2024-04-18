ifdef FD_HAS_ROCKSDB

ifdef FD_HAS_ZSTD
$(call make-bin,fd_frank_ledger,main,fd_flamenco fd_ballet fd_funk fd_util,$(ROCKSDB_LIBS))
else
$(warning ledger tool build disabled due to lack of zstd)
endif

else
$(warning ledger tool build disabled due to lack of rocksdb)
endif
