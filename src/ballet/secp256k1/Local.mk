ifdef FD_HAS_S2NBIGNUM
$(call add-hdrs,fd_secp256k1.h)
$(call add-objs,fd_secp256k1,fd_ballet)
$(call make-unit-test,test_secp256k1,test_secp256k1,fd_ballet fd_util)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_secp256k1_recover,fuzz_secp256k1_recover,fd_ballet fd_util)
endif

$(call run-unit-test,test_secp256k1)
endif
