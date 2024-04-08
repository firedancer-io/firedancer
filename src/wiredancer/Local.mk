ifdef FD_HAS_WIREDANCER
$(call make-lib,fd_wiredancer)
$(call add-hdrs,c/wd_f1.h)
$(call add-objs,c/wd_f1,fd_wiredancer)
endif
