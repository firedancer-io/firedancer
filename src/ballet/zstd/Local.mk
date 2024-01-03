ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_zstd.h)
$(call add-objs,fd_zstd,fd_util)
$(call make-unit-test,test_zstd,test_zstd,fd_util)
$(call run-unit-test,test_zstd)
endif
