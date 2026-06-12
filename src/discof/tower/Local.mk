ifdef FD_HAS_HOSTED
$(call add-objs,fd_tower_tile,fd_discof)
$(call make-unit-test,test_tower_tile,test_tower_tile,fd_discof fd_choreo fd_disco fd_flamenco fd_tango fd_ballet fd_util)
endif
