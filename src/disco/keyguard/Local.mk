ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_keyguard.h)
$(call add-objs,fd_keyguard_authorize fd_keyguard_match,fd_disco)
$(call make-unit-test,test_keyguard,test_keyguard,fd_disco fd_flamenco fd_tls fd_ballet fd_util)
$(call run-unit-test,test_keyguard)
$(call make-fuzz-test,fuzz_keyguard,fuzz_keyguard,fd_disco fd_flamenco fd_tls fd_ballet fd_util)

$(call add-hdrs,fd_keyguard_client.h)
$(call add-objs,fd_keyguard_client,fd_disco)

$(call add-hdrs,fd_keyswitch.h)
$(call add-objs,fd_keyswitch,fd_disco)

$(call add-hdrs,fd_keyload.h)
$(call add-objs,fd_keyload,fd_disco)
$(call make-unit-test,test_keyload,test_keyload,fd_disco fd_flamenco fd_tls fd_ballet fd_util)
$(call run-unit-test,test_keyload)
$(call make-proof,proof_authorize,fd_keyguard_proofs.c)

$(call add-objs,fd_sign_tile,fd_disco)
$(call make-unit-test,bench_sign_tile,bench_sign_tile,fd_disco fd_tango fd_flamenco fd_tls fd_ballet fd_util)
$(call make-unit-test,test_sign_tile,test_sign_tile,fd_disco fd_tango fd_flamenco fd_tls fd_ballet fd_util)
$(call run-unit-test,test_sign_tile)
endif
endif
