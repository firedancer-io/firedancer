$(call add-hdrs,fd_vinyl_line.h)
$(call add-objs,fd_vinyl_line,fd_vinyl)
$(call make-unit-test,test_vinyl_line,test_vinyl_line,fd_vinyl fd_tango fd_util)
$(call run-unit-test,test_vinyl_line)
