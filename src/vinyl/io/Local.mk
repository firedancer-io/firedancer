ifdef FD_HAS_LZ4
$(call add-hdrs,fd_vinyl_io.h)
$(call add-objs,fd_vinyl_io fd_vinyl_io_bd fd_vinyl_io_mm,fd_vinyl)
$(call make-unit-test,test_vinyl_io_bd,test_vinyl_io_bd,fd_vinyl fd_tango fd_util)
$(call make-unit-test,test_vinyl_io_mm,test_vinyl_io_mm,fd_vinyl fd_tango fd_util)
$(call run-unit-test,test_vinyl_io_bd)
$(call run-unit-test,test_vinyl_io_mm)
endif

$(call add-hdrs,fd_vinyl_io_ur.h)
$(call add-objs,fd_vinyl_io_ur,fd_vinyl)
$(call make-unit-test,test_vinyl_io_ur,test_vinyl_io_ur,fd_vinyl fd_tango fd_util)
