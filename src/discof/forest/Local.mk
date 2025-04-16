ifdef FD_HAS_INT128
$(call add-objs,fd_forest,fd_discof)
$(call make-unit-test,test_forest,test_forest,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
endif
