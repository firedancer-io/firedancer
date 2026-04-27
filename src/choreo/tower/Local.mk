$(call add-hdrs,fd_tower.h fd_tower_serde.h)
$(call add-objs,fd_tower,fd_choreo)
$(call add-objs,fd_tower_serde,fd_choreo)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_tower,test_tower,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call make-unit-test,test_tower_serde,test_tower_serde,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_tower_serde)
$(call make-fuzz-test,fuzz_tower_serde,fuzz_tower_serde,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
endif
