$(call add-hdrs,fd_compress.h)
$(call add-objs,fd_compress,fd_util)
$(call make-unit-test,test_decompress,test_decompress,fd_util)
$(call run-unit-test,test_decompress)
