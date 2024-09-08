$(call add-hdrs,fd_aes_base.h fd_aes_gcm.h)
$(call add-objs,fd_aes_base_ref,fd_ballet)
$(call add-objs,fd_aes_gcm_ref fd_aes_gcm_ref_ghash,fd_ballet)
ifdef FD_HAS_X86
$(call add-objs,fd_aes_gcm_x86,fd_ballet)
ifdef FD_HAS_AESNI
$(call add-asms,fd_aes_base_aesni,fd_ballet)
$(call add-asms,fd_aes_gcm_aesni,fd_ballet)
ifdef FD_HAS_GFNI
$(call add-asms,fd_aes_gcm_avx10,fd_ballet)
endif
endif
endif
$(call make-unit-test,test_aes,test_aes,fd_ballet fd_util)
