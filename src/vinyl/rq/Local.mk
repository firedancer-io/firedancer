$(call add-hdrs,fd_vinyl_rq.h)
$(call add-objs,fd_vinyl_rq,fd_vinyl)
$(call make-unit-test,test_vinyl_rq,test_vinyl_rq,fd_vinyl fd_tango fd_util)
$(call run-unit-test,test_vinyl_rq)
