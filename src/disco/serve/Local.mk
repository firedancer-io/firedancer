ifdef FD_HAS_OPENSSL
$(call add-hdrs,fd_serve.h)
$(call add-objs,fd_serve,fd_disco)
$(call make-unit-test,test_serve_tile,test_serve_tile,fd_disco fd_tango fd_ballet fd_quic fd_util)
endif
