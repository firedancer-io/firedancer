$(call add-hdrs,fd_aes_base.h fd_aes_gcm.h fd_aes_gcm_ref.h)
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
# portable backend: production only without AESNI, else exercised by test_aes
ifdef FD_HAS_AESNI
TEST_AES_OBJS:=test_aes fd_aes_base_ref
else
$(call add-objs,fd_aes_base_ref,fd_ballet)
$(call add-objs,fd_aes_gcm_ref fd_aes_gcm_ref_ghash,fd_ballet)
TEST_AES_OBJS:=test_aes
endif
$(call make-unit-test,test_aes,$(TEST_AES_OBJS),fd_ballet fd_util)
$(call run-unit-test,test_aes)
