$(call add-hdrs,fd_keyguard.h fd_keyload.h fd_keyguard_client.h)
$(call add-objs,fd_keyguard_match fd_keyguard_client fd_keyload,fd_disco)
$(call make-unit-test,test_keyload,test_keyload,fd_disco fd_util)
