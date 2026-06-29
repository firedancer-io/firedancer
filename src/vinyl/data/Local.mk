$(call add-hdrs,fd_vinyl_data.h)
$(call add-objs,fd_vinyl_data fd_vinyl_data_szc_cfg,fd_vinyl)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_vinyl_data,test_vinyl_data,fd_vinyl fd_tango fd_util)
$(call run-unit-test,test_vinyl_data)
endif
