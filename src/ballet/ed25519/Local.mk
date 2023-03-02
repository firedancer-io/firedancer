$(call add-hdrs,fd_ed25519.h)
$(call add-objs,fd_ed25519_fe fd_ed25519_ge fd_ed25519_user,fd_ballet)
$(call make-unit-test,test_ed25519,test_ed25519,fd_ballet fd_util)
$(call run-unit-test,test_ed25519,)
