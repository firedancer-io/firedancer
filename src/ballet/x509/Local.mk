$(call add-hdrs,fd_x509_cert_parser.h fd_x509_common.h fd_x509_config.h fd_x509_utils.h)
$(call add-objs,fd_x509_cert_parser fd_x509_common,fd_ballet)
ifdef FD_HAS_OPENSSL
$(call add-hdrs,fd_x509_openssl.h)
$(call add-objs,fd_x509_openssl,fd_ballet)
endif
