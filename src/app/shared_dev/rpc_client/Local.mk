ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_rpc_client.h)
$(call add-objs,fd_rpc_client,fd_app_dev)
$(call make-unit-test,test_rpc_client,test_rpc_client,fd_app_dev fd_waltz fd_ballet fd_util)
$(call make-unit-test,dump_rpc_client,dump_rpc_client,fd_app_dev fd_waltz fd_ballet fd_util)
$(call run-unit-test,test_rpc_client)
endif
