$(call add-hdrs,fd_cnc.h)
$(call add-objs,fd_cnc,fd_tango)
$(call make-unit-test,test_cnc,test_cnc,fd_tango fd_util)

