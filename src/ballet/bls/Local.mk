ifdef FD_HAS_BLST

$(call add-hdrs,fd_bls12_381.h)
$(call add-objs,fd_bls12_381,fd_ballet)
$(call make-unit-test,test_bls12_381,test_bls12_381,fd_ballet fd_util,$(BLST_LIBS))

$(call run-unit-test,test_bls12_381)

else

$(warning bls12_381 disabled due to lack of libblst)

endif
