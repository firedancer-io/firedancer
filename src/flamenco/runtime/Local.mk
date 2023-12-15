ifdef FD_HAS_INT128
$(call add-hdrs,fd_runtime.h fd_rent_lists.h)
$(call add-hdrs,fd_acc_mgr.h)
$(call add-objs,fd_acc_mgr,fd_flamenco)
endif
