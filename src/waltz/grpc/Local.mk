$(call add-hdrs,fd_grpc_codec.h)
$(call add-objs,fd_grpc_codec,fd_waltz)
$(call make-unit-test,test_grpc_codec,test_grpc_codec,fd_waltz fd_ballet fd_util)
$(call run-unit-test,test_grpc_codec)
$(call make-unit-test,test_grpc_client,test_grpc_client,fd_waltz fd_ballet fd_util,$(OPENSSL_LIBS))
$(call run-unit-test,test_grpc_client)

$(call add-hdrs,fd_grpc_client.h)
$(call add-objs,fd_grpc_client,fd_waltz)
