$(call add-hdrs,fd_tlsrec.h fd_tlsrec_frag.h)
$(call add-objs,fd_tlsrec,fd_waltz)
$(call make-unit-test,test_tlsrec,test_tlsrec,fd_waltz fd_tls fd_ballet fd_util)
$(call run-unit-test,test_tlsrec)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_tlsrec,fuzz_tlsrec,fd_waltz fd_tls fd_ballet fd_util)
endif

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_tlsrec_sock.h)
$(call add-objs,fd_tlsrec_sock,fd_waltz)
endif
