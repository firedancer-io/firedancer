$(call add-hdrs,fd_poh.h)
$(call add-objs,fd_poh,fddev_shared)
$(call make-unit-test,test_poh,test_poh fd_poh,fd_ballet fd_util)
$(call run-unit-test,test_poh)
