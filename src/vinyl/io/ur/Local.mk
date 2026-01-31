ifdef FD_HAS_LINUX
ifdef FD_HAS_LZ4
$(call add-hdrs,fd_vinyl_io_ur.h)
$(call add-objs,fd_vinyl_io_ur fd_vinyl_io_ur_rd fd_vinyl_io_ur_wb,fd_vinyl)
$(call make-unit-test,test_vinyl_io_ur,test_vinyl_io_ur,fd_vinyl fd_tango fd_util)
endif
endif
