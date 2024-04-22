ifdef FD_HAS_ROCKSDB
ifdef FD_HAS_INT128
$(call add-hdrs,fd_repair.h)
$(call add-objs,fd_repair,fd_flamenco)
$(call make-bin,fd_repair_tool,fd_repair_tool,fd_ballet fd_funk fd_util fd_flamenco)
endif
endif
