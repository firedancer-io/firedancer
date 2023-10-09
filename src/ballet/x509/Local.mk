$(call add-hdrs,fd_x509.h)
ifdef FD_HAS_OPENSSL
$(call add-objs,fd_x509,fd_ballet)
endif
