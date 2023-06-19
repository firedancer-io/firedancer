$(call make-lib,fd_tls)
$(call add-hdrs,fd_tls.h fd_tls_proto.h)
$(call add-objs,fd_tls fd_tls_proto,fd_tls)
$(call make-unit-test,test_tls_proto,test_tls_proto,fd_util fd_tls)
