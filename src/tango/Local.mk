$(call make-lib,fd_tango)
$(call add-hdrs,fd_tango_base.h fd_tango.h)
$(call make-bin,fd_tango_ctl,fd_tango_ctl,fd_tango fd_util)
$(call make-unit-test,test_tango_base,test_tango_base,fd_tango fd_util)

