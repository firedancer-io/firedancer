ifdef FD_HAS_INT128
$(call add-objs,fd_shred_dest,fd_disco)
$(call make-unit-test,test_shred_dest,test_shred_dest,fd_ballet fd_util fd_flamenco fd_disco)
$(call run-unit-test,test_shred_dest)
endif
