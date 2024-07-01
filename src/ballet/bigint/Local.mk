$(call add-hdr,fd_uint256.h fd_uint256_mul.h)
$(call make-unit-test,test_uint256,test_uint256,fd_util)
$(call run-unit-test,test_uint256)
