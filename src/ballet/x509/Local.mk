ifdef FD_HAS_OPENSSL
$(call add-hdrs,fd_x509_openssl.h)
$(call add-objs,fd_x509_openssl,fd_ballet)
endif
