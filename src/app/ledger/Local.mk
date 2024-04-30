ifdef FD_HAS_ROCKSDB

ifdef FD_HAS_ZSTD
$(call make-bin,fd_ledger,main,fd_flamenco fd_ballet fd_reedsol fd_disco fd_funk fd_shred fd_tango fd_choreo fd_waltz fd_util,$(ROCKSDB_LIBS) $(SECP256K1_LIBS))
else
$(warning ledger tool build disabled due to lack of zstd)
endif

else
$(warning ledger tool build disabled due to lack of rocksdb)
endif
