$(call add-hdrs,fd_bits.h fd_bits_find_lsb.h fd_bits_find_msb.h fd_float.h fd_uwide.h)
$(call make-unit-test,test_bits,test_bits,fd_util)
$(call make-unit-test,test_float,test_float,fd_util)
$(call make-unit-test,test_hash,test_hash,fd_util)
$(call make-unit-test,test_uwide,test_uwide,fd_util)

