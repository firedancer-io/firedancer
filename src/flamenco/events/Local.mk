ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_event_runtime.h)
$(call add-objs,fd_event_tl fd_event_runtime,fd_flamenco)
endif
