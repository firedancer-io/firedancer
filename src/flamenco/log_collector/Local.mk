$(call add-hdrs,fd_log_collector.h)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_log_collector,test_log_collector,fd_flamenco fd_ballet fd_util)
endif
