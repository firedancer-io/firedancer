$(call add-hdrs,fd_vinyl_cq.h)
$(call add-objs,fd_vinyl_cq,fd_vinyl)
$(call make-unit-test,test_vinyl_cq,test_vinyl_cq,fd_vinyl fd_tango fd_util)
$(call run-unit-test,test_vinyl_cq)
