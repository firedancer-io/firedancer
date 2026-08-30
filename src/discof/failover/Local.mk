$(call add-hdrs,fd_failover_proto.h)
$(call add-objs,fd_failover_proto,fd_discof)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_failover_proto,test_failover_proto,fd_discof fd_util)
$(call run-unit-test,test_failover_proto)
endif
