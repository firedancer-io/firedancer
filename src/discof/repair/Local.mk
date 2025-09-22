ifdef FD_HAS_INT128
$(call add-objs,fd_repair_tile,fd_discof)
$(call add-objs,fd_policy,fd_discof)
$(call add-hdrs,fd_policy.h)
$(call add-objs,fd_inflight,fd_discof)
$(call add-hdrs,fd_inflight.h)
$(call add-objs,fd_repair,fd_discof)
$(call add-hdrs,fd_repair.h)
$(call add-objs,fd_catchup,fd_discof)
$(call add-hdrs,fd_catchup.h)
endif
