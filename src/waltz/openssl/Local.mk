$(call add-hdrs,fd_openssl.h)
ifdef FD_HAS_OPENSSL
$(call add-objs,fd_openssl,fd_waltz)
endif
