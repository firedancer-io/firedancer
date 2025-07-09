$(call add-objs,fd_verify_tile,fd_disco)
$(call make-unit-test,test_tiles_verify,test_verify,fd_ballet fd_tango fd_util)
$(call run-unit-test,test_tiles_verify)
