$(call add-hdrs,fd_merlin.h)
$(call add-objs,fd_merlin,fd_ballet)
$(call make-unit-test,test_merlin,test_merlin,fd_ballet fd_util)
$(call run-unit-test,test_merlin)
