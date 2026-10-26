$(call add-hdrs,fd_bls12_381.h fd_bls.h)

ifdef FD_HAS_AVX512
$(call add-objs,fd_bls12_381 avx512/fd_bls_rns avx512/fd_bls_field avx512/fd_bls_final \
  avx512/fd_bls_g2 avx512/fd_bls_miller avx512/fd_bls_g1 avx512/fd_bls_hash avx512/fd_bls,fd_ballet)
else
$(call add-objs,fd_bls12_381 ref/fd_bls,fd_ballet)
endif

$(call make-unit-test,test_bls12_381,test_bls12_381,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls12_381)
