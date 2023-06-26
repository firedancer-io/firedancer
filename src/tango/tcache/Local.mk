$(call add-hdrs,fd_tcache.h)
$(call add-objs,fd_tcache,fd_tango)
$(call make-unit-test,test_tcache,test_tcache,fd_tango fd_util)

