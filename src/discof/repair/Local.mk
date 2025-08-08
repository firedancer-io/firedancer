ifdef FD_HAS_INT128
$(call add-objs,fd_reasm,fd_discof)
$(call add-objs,fd_repair_tile,fd_discof)
$(call make-unit-test,test_reasm,test_reasm,fd_discof fd_flamenco fd_ballet fd_util)
endif
