ifdef FD_HAS_ROCKSDB

ifdef FD_HAS_ZSTD
ifdef FD_HAS_SECP256K1
$(call make-bin,fd_ledger,main,fd_disco fd_flamenco fd_ballet fd_reedsol fd_funk fd_shred fd_tango fd_choreo fd_waltz fd_util,$(ROCKSDB_LIBS) $(SECP256K1_LIBS))
else
$(warning ledger tool build disabled due to lack of secp256k1)
endif
else
$(warning ledger tool build disabled due to lack of zstd)
endif

else
$(warning ledger tool build disabled due to lack of rocksdb)
endif
