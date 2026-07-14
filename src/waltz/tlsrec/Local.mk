$(call add-hdrs,fd_tlsrec.h fd_tlsrec_frag.h)
$(call add-objs,fd_tlsrec,fd_waltz)
$(call make-unit-test,test_tlsrec,test_tlsrec,fd_waltz fd_tls fd_ballet fd_util)
$(call run-unit-test,test_tlsrec)
