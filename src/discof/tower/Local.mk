ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_LZ4
$(call add-objs,fd_tower_tile,fd_discof)
$(call make-unit-test,test_tower_tile,test_tower_tile,fd_discof fd_choreo fd_disco fd_flamenco fd_vinyl fd_tango fd_ballet fd_util)
$(call run-unit-test,test_tower_tile)
endif
endif
endif
