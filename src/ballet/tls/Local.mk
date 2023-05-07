$(call add-hrs,fd_tls_keylog.h)
$(call add-objs,fd_tls_keylog,fd_ballet)
$(call make-unit-test,test_tls_keylog,test_tls_keylog,fd_ballet fd_util)
$(call run-unit-test,test_tls_keylog)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_tls_keylog_parse,fuzz_tls_keylog,fd_ballet fd_util)
endif

