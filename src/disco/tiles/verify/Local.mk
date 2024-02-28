$(call add-hdrs,fd_verify_tile.h generated/fd_verify_tile_seccomp.h)
$(call add-objs,fd_verify_tile,fd_disco)
$(call make-unit-test,test_tiles_verify,test_verify,fd_ballet fd_tango fd_util)
$(call run-unit-test,test_tiles_verify)
