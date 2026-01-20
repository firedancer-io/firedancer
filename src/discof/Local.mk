$(call make-lib,fd_discof)
$(call add_hdrs,fd_discof.h)

$(call add-hdrs,fd_accdb_topo.h)
$(call add-objs,fd_accdb_topo,fd_discof)
