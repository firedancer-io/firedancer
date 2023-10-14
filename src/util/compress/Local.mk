ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_compress.h)
$(call add-objs,fd_compress,fd_util)
endif
