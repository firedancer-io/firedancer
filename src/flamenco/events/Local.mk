ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_event_runtime.h fd_event_internal.h)
$(call add-objs,fd_event_tl fd_event_runtime fd_event_internal,fd_flamenco)
endif
