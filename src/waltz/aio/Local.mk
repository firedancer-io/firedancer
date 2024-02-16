$(call add-hdrs,fd_aio.h fd_aio_pcapng.h)
$(call add-objs,fd_aio fd_aio_pcapng,fd_util)
$(call make-unit-test,test_aio,test_aio,fd_waltz fd_util)
$(call run-unit-test,test_aio)
