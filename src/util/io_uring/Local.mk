ifdef FD_HAS_LINUX
$(call add-hdrs,fd_io_uring.h)
$(call add-hdrs,fd_io_uring_register.h)
$(call add-hdrs,fd_io_uring_setup.h)

$(call add-objs,fd_io_uring,fd_util)
$(call add-objs,fd_io_uring_setup,fd_util)
endif
