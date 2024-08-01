ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_keyguard.h fd_keyload.h fd_keyguard_client.h)
$(call add-objs,fd_keyguard_match fd_keyguard_client fd_keyload,fd_disco)
$(call make-unit-test,test_keyload,test_keyload,fd_disco fd_ballet fd_util)
endif
endif
