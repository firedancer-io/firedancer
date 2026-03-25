ifdef FD_HAS_ROCKSDB

$(call make-bin,fd_ledger,main,fd_flamenco fd_ballet fd_reedsol fd_funk fd_tango fd_choreo fd_waltz fd_util fd_disco,$(ROCKSDB_LIBS) $(SECP256K1_LIBS))

else
$(warning ledger tool build disabled due to lack of rocksdb)
endif
