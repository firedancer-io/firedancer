$(call add-hdrs,fd_aio.h)
$(call add-objs,fd_aio,fd_waltz)
$(call make-unit-test,test_aio,test_aio,fd_waltz fd_util)
$(call run-unit-test,test_aio)

$(call add-hdrs,fd_aio_pcapng.h)
$(call add-objs,fd_aio_pcapng,fd_waltz)

$(call add-hdrs,fd_aio_tango.h)
$(call add-objs,fd_aio_tango,fd_waltz)
