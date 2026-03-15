ifdef FD_HAS_HOSTED
ifneq (,$(filter 1,$(FD_HAS_LINUX) $(FD_HAS_DARWIN)))
$(call add-hdrs,fd_keyguard.h)
$(call add-objs,fd_keyguard_authorize fd_keyguard_match,fd_disco)

$(call add-hdrs,fd_keyguard_client.h)
$(call add-objs,fd_keyguard_client,fd_disco)

$(call add-hdrs,fd_keyswitch.h)
$(call add-objs,fd_keyswitch,fd_disco)

$(call add-hdrs,fd_keyload.h)
$(call add-objs,fd_keyload,fd_disco)
$(call make-unit-test,test_keyload,test_keyload,fd_disco fd_flamenco fd_tls fd_ballet fd_util)
$(call make-proof,proof_authorize,fd_keyguard_proofs.c)
endif
endif
