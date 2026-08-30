ifdef FD_HAS_HOSTED
$(call add-objs,fd_rotor_tile,fd_discof)
$(call make-unit-test,test_rotor_tile,test_rotor_tile,fd_discof fd_disco fd_choreo fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_rotor_tile)
endif
$(call add-hdrs,fd_rotor_tile.h)
