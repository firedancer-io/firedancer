ifdef FD_HAS_HOSTED
$(call make-bin,fd_zstd_pack,fd_zstd_pack,fd_util)
$(call make-bin,fd_gzip_pack,fd_gzip_pack,fd_zlib fd_util)
endif
