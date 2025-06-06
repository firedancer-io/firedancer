ifdef FD_HAS_INT128
$(call add-hdrs,fd_repair.h)
$(call add-objs,fd_repair,fd_flamenco)
ifdef FD_HAS_HOSTED
#$(call make-bin,fd_repair_tool,fd_repair_tool,fd_flamenco fd_ballet fd_util)
endif
endif
