ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_event_report.h)
$(call add-hdrs,generated/fd_event_gen.h)
$(call add-objs,fd_event_client fd_event_report,fd_disco)
$(call add-objs,generated/fd_event_gen,fd_disco)
$(call add-objs,fd_event_tile,fd_disco)
endif
