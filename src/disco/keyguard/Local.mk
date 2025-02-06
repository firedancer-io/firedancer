ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_keyguard.h)
$(call add-objs,fd_keyguard_authorize fd_keyguard_match,fd_disco)

$(call add-hdrs,fd_keyguard_client.h)
$(call add-objs,fd_keyguard_client,fd_disco)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_keyswitch.h)
$(call add-objs,fd_keyswitch,fd_disco)
endif

$(call add-hdrs,fd_keyload.h)
$(call add-objs,fd_keyload,fd_disco)
$(call make-unit-test,test_keyload,test_keyload,fd_disco fd_util)
endif
endif
