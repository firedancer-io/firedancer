ifdef FD_HAS_SSE
$(call add-objs,fd_repair_tile fd_repair,fd_discof)
$(call make-unit-test,test_repair,test_repair,fd_choreo fd_flamenco fd_ballet fd_util fd_discof)
endif
