ifdef FD_HAS_ROCKSDB
$(call make-bin,fd_shred_cap,main,fd_flamenco fd_ballet fd_funk fd_util,$(ROCKSDB_LIBS))
else
$(warning shredcap capture tool build disabled due to lack of rocksdb)
endif
