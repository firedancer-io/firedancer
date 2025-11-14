$(call add-hdrs,fd_vinyl_meta.h)
$(call add-objs,fd_vinyl_meta,fd_vinyl)
$(call make-unit-test,test_vinyl_meta,test_vinyl_meta,fd_vinyl fd_tango fd_util)
$(call run-unit-test,test_vinyl_meta)
