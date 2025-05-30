$(call add-hdrs,fd_mbedtls.h)
ifdef FD_HAS_MBEDTLS
$(call add-hdrs,fd_mbedtls_config.h)
$(call add-objs,fd_mbedtls,fd_waltz)
endif
