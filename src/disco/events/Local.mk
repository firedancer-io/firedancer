ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_circq.h fd_event_report.h)
$(call add-hdrs,generated/fd_event_gen.h)
$(call add-objs,fd_circq fd_event_client fd_event_report,fd_disco)
$(call add-objs,generated/fd_event_gen,fd_disco)
$(call add-objs,fd_event_tile,fd_disco)

$(call make-unit-test,test_circq,test_circq,fd_disco fd_flamenco fd_tango fd_util)
$(call run-unit-test,test_circq)
$(call make-unit-test,test_event_client,test_event_client,fd_disco fd_waltz fd_flamenco fd_tango fd_ballet fd_util,$(OPENSSL_LIBS))
$(call run-unit-test,test_event_client)
endif
