$(call add-hdrs,fd_rotor.h)
$(call add-objs,fd_rotor,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_rotor,test_rotor,fd_choreo fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_rotor)
endif
