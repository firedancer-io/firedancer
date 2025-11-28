ifdef FD_HAS_LZ4
$(call make-lib,fd_vinyl)
$(call add-hdrs,fd_vinyl_base.h fd_vinyl.h)
$(call add-objs,fd_vinyl_base fd_vinyl_recover fd_vinyl_compact fd_vinyl_cmd fd_vinyl fd_vinyl_exec,fd_vinyl)
ifdef FD_HAS_HOSTED
$(call make-bin,fd_vinyl_ctl,fd_vinyl_ctl,fd_vinyl fd_tango fd_util)
endif
$(call make-unit-test,test_vinyl_base,test_vinyl_base,fd_vinyl fd_tango fd_util)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_vinyl_req,test_vinyl_req,fd_vinyl fd_tango fd_util)
endif
$(call run-unit-test,test_vinyl_base)
endif
