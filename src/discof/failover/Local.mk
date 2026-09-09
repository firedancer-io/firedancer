$(call add-hdrs,fd_failover_proto.h fd_failover_wire.h fd_failover_channel.h fd_failover_stream.h)
$(call add-objs,fd_failover_proto,fd_discof)
$(call add-objs,fd_failover_wire,fd_discof)
$(call add-objs,fd_failover_channel,fd_discof)
$(call add-objs,fd_failover_stream,fd_discof)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_failover_proto,test_failover_proto,fd_discof fd_util)
$(call run-unit-test,test_failover_proto)
$(call make-unit-test,test_failover_wire,test_failover_wire,fd_discof fd_ballet fd_util)
$(call run-unit-test,test_failover_wire)
$(call make-unit-test,test_failover_channel,test_failover_channel,fd_discof fd_ballet fd_util)
$(call run-unit-test,test_failover_channel)
$(call make-unit-test,test_failover_stream,test_failover_stream,fd_discof fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_failover_stream)
endif
