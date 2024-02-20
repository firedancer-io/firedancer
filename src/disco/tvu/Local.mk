ifdef FD_HAS_INT128
$(call add-hdrs,fd_replay.h fd_tvu.h)
$(call add-objs,fd_replay fd_tvu,fd_disco)
$(call make-unit-test,test_runtime,test_runtime,fd_disco fd_flamenco fd_funk fd_tango fd_util fd_ballet fd_reedsol)
endif
