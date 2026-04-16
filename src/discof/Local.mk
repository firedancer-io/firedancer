$(call make-lib,fd_discof)
$(call add_hdrs,fd_discof.h)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_accdb_topo.h)
$(call add-objs,fd_accdb_topo,fd_discof)

$(call add-hdrs,fd_startup.h)
$(call add-objs,fd_startup,fd_discof)
endif
