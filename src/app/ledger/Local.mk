ifneq ($(FD_HAS_ROCKSDB),)

ifeq ($(FD_HAS_ZSTD),1)
$(call make-bin,fd_frank_ledger,main,fd_ballet fd_funk fd_util fd_flamenco)
else
$(warning ledger tool build disabled due to lack of zstd)
endif

else
$(warning ledger tool build disabled due to lack of rocksdb)
endif
