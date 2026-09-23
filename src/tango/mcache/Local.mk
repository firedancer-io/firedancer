$(call add-hdrs,fd_mcache.h)
$(call add-objs,fd_mcache,fd_tango)
$(call make-unit-test,test_mcache,test_mcache,fd_tango fd_util)
$(call run-unit-test,test_mcache)
ifdef FD_HAS_THREADS
$(call make-unit-test,test_mcache_ordering,test_mcache_ordering,fd_tango fd_util)
endif

