$(call add-hdrs,fd_tower_serdes.h)
$(call add-objs,fd_tower_serdes,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_tower_serdes,test_tower_serdes,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_tower_serdes)
$(call make-fuzz-test,fuzz_tower_serdes,fuzz_tower_serdes,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
endif
