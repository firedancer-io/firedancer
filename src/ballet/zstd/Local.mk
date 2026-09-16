ifdef FD_HAS_HOSTED
$(call make-tool,fd_zstd_pack,fd_zstd_pack,fd_zstd)
$(call make-tool,fd_gzip_pack,fd_gzip_pack,fd_zlib)
endif
