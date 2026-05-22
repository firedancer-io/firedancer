$(call make-lib,fd_discof)

$(call add-hdrs,fd_funk_pkeys.h)
$(call add-objs,fd_funk_pkeys,fd_discof)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_accdb_topo.h)
$(call add-objs,fd_accdb_topo,fd_discof)

$(call add-hdrs,fd_startup.h)
$(call add-objs,fd_startup,fd_discof)
endif
