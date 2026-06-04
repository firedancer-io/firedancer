ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_circq.h)
$(call add-objs,fd_circq fd_event_client,fd_disco)
$(call add-objs,fd_event_tile,fd_disco)

$(call make-unit-test,test_circq,test_circq,fd_disco fd_flamenco fd_tango fd_util)
$(call run-unit-test,test_circq)
endif
