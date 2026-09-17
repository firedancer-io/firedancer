$(call add-hdrs,fd_reedsol.h)
ifdef FD_HAS_GFNI
$(call add-asms,fd_reedsol_gfni_32,fd_reedsol)
endif
$(call add-objs,fd_reedsol,fd_reedsol)
$(call add-objs,fd_reedsol_encode_16,fd_reedsol)
$(call add-objs,fd_reedsol_encode_32,fd_reedsol)
$(call add-objs,fd_reedsol_encode_64,fd_reedsol)
$(call add-objs,fd_reedsol_encode_128,fd_reedsol)
$(call add-objs,fd_reedsol_recover_16,fd_reedsol)
$(call add-objs,fd_reedsol_recover_32,fd_reedsol)
$(call add-objs,fd_reedsol_recover_64,fd_reedsol)
$(call add-objs,fd_reedsol_recover_128,fd_reedsol)
$(call add-objs,fd_reedsol_recover_256,fd_reedsol)
$(call add-objs,fd_reedsol_pi,fd_reedsol)
ifdef FD_HAS_HOSTED
TEST_REEDSOL_OBJS:=test_reedsol \
  wrapped_impl/fd_reedsol_ppt_impl_17 wrapped_impl/fd_reedsol_ppt_impl_25 \
  wrapped_impl/fd_reedsol_fft_impl_64_0 wrapped_impl/fd_reedsol_fft_impl_64_64 wrapped_impl/fd_reedsol_fft_impl_64_128 \
  wrapped_impl/fd_reedsol_ifft_impl_64_0 wrapped_impl/fd_reedsol_ifft_impl_64_64 wrapped_impl/fd_reedsol_ifft_impl_64_128 \
  wrapped_impl/fd_reedsol_ifft_impl_128_128
$(call make-unit-test,test_reedsol,$(TEST_REEDSOL_OBJS),fd_reedsol fd_util)
$(call make-fuzz-test,fuzz_reedsol,fuzz_reedsol,fd_reedsol fd_util)
endif
