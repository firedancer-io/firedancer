ifdef FD_HAS_INT128
$(call add-hdrs,fd_bundle_crank.h)
$(call add-objs,fd_bundle_crank,fd_disco,fd_flamenco)
$(call make-unit-test,test_bundle_crank,test_bundle_crank,fd_disco fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_bundle_crank)
endif

$(call add-hdrs,fd_bundle_tile.h)
$(call add-objs,fd_bundle_auth fd_bundle_client,fd_disco)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SSE
$(call make-unit-test,test_bundle_client,test_bundle_client,fd_disco fd_waltz fd_flamenco fd_tango fd_ballet fd_util,$(OPENSSL_LIBS))
endif
$(call make-fuzz-test,fuzz_bundle_auth_resp,fuzz_bundle_auth_resp,fd_disco fd_waltz fd_flamenco fd_tango fd_ballet fd_util,$(OPENSSL_LIBS))
endif

ifdef FD_HAS_SSE # implies FD_HAS_DOUBLE
$(call add-objs,fd_bundle_tile,fd_disco)
endif
