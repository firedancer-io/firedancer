ifneq ($(FD_HAS_SECP256K1),)

$(call add-hdrs,fd_secp256k1.h)
$(call add-objs,fd_secp256k1,fd_ballet)
$(call make-unit-test,test_secp256k1,test_secp256k1,fd_ballet fd_util,$(SECP256K1_LIBS))
$(call fuzz-test,fuzz_secp256k1_recover,fuzz_secp256k1_recover,fd_ballet fd_util)

$(call run-unit-test,test_secp256k1)

else

$(warning secp256k1 disabled due to lack of libsecp256k1)

endif
