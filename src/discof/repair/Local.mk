ifdef FD_HAS_ALLOCA
$(call add-objs,fd_repair_tile,fd_discof)
endif
$(call add-objs,fd_policy,fd_discof)
$(call add-hdrs,fd_policy.h)
$(call add-objs,fd_inflight,fd_discof)
$(call add-hdrs,fd_inflight.h)
$(call add-objs,fd_repair,fd_discof)
$(call add-hdrs,fd_repair.h)
$(call add-objs,fd_repair_metrics,fd_discof)
$(call add-hdrs,fd_repair_metrics.h)
$(call make-unit-test,test_policy,test_policy,fd_discof fd_disco fd_tango fd_ballet fd_util)