ifdef FD_HAS_INT128

$(call add-hdrs,fd_log_collector.h)
$(call make-unit-test,test_log_collector,test_log_collector,fd_flamenco fd_ballet fd_util)

endif
