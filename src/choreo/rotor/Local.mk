$(call add-hdrs,fd_rotor.h fd_rotor_serde.h fd_rotor_strat.h)
$(call add-objs,fd_rotor fd_rotor_serde fd_rotor_strat,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_fd_rotor,test_fd_rotor,fd_choreo fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_fd_rotor)
$(call make-unit-test,test_fd_rotor_serde,test_fd_rotor_serde,fd_choreo fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_fd_rotor_serde)
$(call make-unit-test,test_fd_rotor_strat,test_fd_rotor_strat,fd_choreo fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_fd_rotor_strat)
endif
