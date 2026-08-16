ifdef FD_HAS_HOSTED
$(call add-objs,fd_poh_tile fd_poh,fd_discof)
$(call make-unit-test,test_poh_ag_marker,test_poh_ag_marker,fd_discof fd_disco fd_flamenco fd_ballet fd_tango fd_util)
$(call run-unit-test,test_poh_ag_marker)
endif
