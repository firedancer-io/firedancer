$(call add-hdrs,fd_ed25519.h fd_x25519.h)
$(call add-objs,fd_ed25519_fe fd_ed25519_ge fd_ed25519_user fd_x25519,fd_ballet)
$(call make-unit-test,test_ed25519,test_ed25519,fd_ballet fd_util)
$(call make-unit-test,test_ed25519_signature_malleability,test_ed25519_signature_malleability,fd_ballet fd_util)
$(call make-unit-test,test_ed25519_wycheproof,test_ed25519_wycheproof,fd_ballet fd_util)
$(call make-unit-test,test_x25519,test_x25519,fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ed25519_verify,fuzz_ed25519_verify,fd_ballet fd_util)
$(call make-fuzz-test,fuzz_ed25519_sigverify,fuzz_ed25519_sigverify,fd_ballet fd_util)

$(call run-unit-test,test_ed25519)
$(call run-unit-test,test_ed25519_signature_malleability)
$(call run-unit-test,test_ed25519_wycheproof)
$(call run-unit-test,test_x25519)

