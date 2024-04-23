ifdef FD_HAS_ROCKSDB
$(call add-hdrs,fd_shredcap.h)
$(call add-objs,fd_shredcap,fd_flamenco)
endif
