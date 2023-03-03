$(call add-hdrs,fd_mcache.h)
$(call add-objs,fd_mcache,fd_tango)
$(call make-unit-test,test_mcache,test_mcache,fd_tango fd_util)
$(call run-unit-test,test_mcache,)

