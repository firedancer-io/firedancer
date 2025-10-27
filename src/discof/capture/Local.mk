ifdef FD_HAS_INT128
ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_capture_ctx.h)
$(call add-objs,fd_capture_ctx fd_capture_tile,fd_discof)
endif
endif
