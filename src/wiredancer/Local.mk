# Legacy F1
ifdef FD_HAS_WIREDANCER
$(call make-lib,fd_wiredancer)
$(call add-hdrs,c/wd_f1.h)
$(call add-objs,c/wd_f1,fd_wiredancer)
endif

# C1100
ifdef FD_HAS_WIREDANCER_C1100
$(call make-lib,fd_wiredancer)
$(call add-hdrs,c/wd_c1100.h)
$(call add-objs,c/wd_c1100,fd_wiredancer)
endif