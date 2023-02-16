$(call add-hdrs,fd_aio.h)
$(call add-objs,fd_aio,fd_util)
$(call make-unit-test,test_aio,test_aio,fd_tango fd_util)
$(call run-unit-test,test_aio)
