$(call make-lib,fd_discof)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_startup.h)
$(call add-objs,fd_startup,fd_discof)
endif
