ifdef FD_HAS_HOSTED
$(call add-objs,fd_motor_tile,fd_discof)
$(call make-unit-test,test_motor_tile,test_motor_tile,fd_discof fd_disco fd_choreo fd_flamenco fd_reedsol fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_motor_tile)
$(call make-unit-test,test_motor_shred,test_motor_shred,fd_disco fd_flamenco fd_ballet fd_reedsol fd_tango fd_util)
$(call run-unit-test,test_motor_shred)
ifdef FD_HAS_LINUX
$(call make-unit-test,test_motor_shred_stem,test_motor_shred_stem,fd_disco fd_flamenco fd_ballet fd_reedsol fd_tango fd_util)
$(call run-unit-test,test_motor_shred_stem)
endif
endif
