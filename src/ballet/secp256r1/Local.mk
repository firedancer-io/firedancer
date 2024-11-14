ifneq ($(wildcard src/ballet/s2n-bignum),)

$(call add-hdrs,fd_secp256r1.h)
$(call add-objs,fd_secp256r1,fd_ballet)
$(call make-unit-test,test_secp256r1,test_secp256r1,fd_ballet fd_util)
$(call run-unit-test,test_secp256r1)

else

$(warning secp256r1 disabled due to lack of s2n-bignum)

endif
