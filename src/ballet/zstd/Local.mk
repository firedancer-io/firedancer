ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_zstd.h)
$(call add-objs,fd_zstd,fd_util)
$(call make-unit-test,test_zstd,test_zstd,fd_util)
$(call run-unit-test,test_zstd)
ifdef FD_HAS_HOSTED
$(call make-bin,fd_zstd_pack,fd_zstd_pack,fd_util)
$(call make-bin,fd_gzip_pack,fd_gzip_pack,fd_zlib fd_util)
endif
endif
