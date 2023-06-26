$(call add-hdrs,fd_dcache.h)
$(call add-objs,fd_dcache,fd_tango)
$(call make-unit-test,test_dcache,test_dcache,fd_tango fd_util)
$(call run-unit-test,test_dcache)

