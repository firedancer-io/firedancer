$(call add-hdrs,fd_aes.h fd_aes_gcm.h)
$(call add-objs,fd_aes fd_aes_ref,fd_ballet)
ifdef FD_HAS_AESNI
$(call add-asms,fd_aesni fd_aesni_gcm,fd_ballet)
endif
ifdef FD_HAS_AVX
$(call add-asms,fd_ghash_avx,fd_ballet)
else
$(call add-objs,fd_ghash_ref,fd_ballet)
endif
$(call make-unit-test,test_aes,test_aes,fd_ballet fd_util)
