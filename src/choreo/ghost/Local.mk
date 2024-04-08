$(call add-hdrs,fd_ghost.h)
$(call add-objs,fd_ghost,fd_choreo)
$(call make-unit-test,test_ghost,test_ghost,fd_choreo fd_util)
$(call run-unit-test,test_ghost,)

