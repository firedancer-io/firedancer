$(call add-hdrs,fd_fctl.h)
$(call add-objs,fd_fctl,fd_tango)
$(call make-unit-test,test_fctl,test_fctl,fd_tango fd_util)
$(call run-unit-test,test_fctl,)

