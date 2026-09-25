$(call add-hdrs,fd_rotor_tile.h fd_schedulor.h fd_requestor.h)
$(call add-objs,fd_schedulor fd_requestor,fd_discof)
ifdef FD_HAS_HOSTED
$(call add-objs,fd_rotor_tile,fd_discof)
$(call make-unit-test,test_rotor_tile,test_rotor_tile,fd_discof fd_disco fd_choreo fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_rotor_tile)
$(call make-unit-test,test_schedulor,test_schedulor,fd_discof fd_util)
$(call run-unit-test,test_schedulor)
$(call make-unit-test,test_requestor,test_requestor,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_requestor)
endif
