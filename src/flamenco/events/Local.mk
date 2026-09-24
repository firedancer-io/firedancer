ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_event_runtime.h)
$(call add-objs,fd_event_tl fd_event_runtime,fd_flamenco)
$(call make-unit-test,test_event_runtime,test_event_runtime,fd_flamenco fd_disco fd_waltz fd_tls fd_tango fd_ballet fd_util)
$(call run-unit-test,test_event_runtime)
endif
