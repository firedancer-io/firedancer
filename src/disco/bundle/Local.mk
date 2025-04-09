$(call add-hdrs,fd_bundle_tile.h)
$(call add-objs,fd_bundle_client,fd_disco)
$(call make-unit-test,test_bundle_client,test_bundle_client,fd_disco fd_waltz fd_flamenco fd_tango fd_ballet fd_util,-lssl -lcrypto)
