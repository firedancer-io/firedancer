$(call add-objs,fd_wksp,fd_util)
$(call add-hdrs,fd_wksp.h)
$(call make-bin,fd_wksp_ctl,fd_wksp_ctl,fd_util)
$(call make-unit-test,test_wksp,test_wksp,fd_util)

