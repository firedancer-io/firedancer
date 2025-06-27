$(call add-hdrs,fd_grpc_codec.h)
$(call add-objs,fd_grpc_codec,fd_waltz)
$(call make-unit-test,test_grpc_codec,test_grpc_codec,fd_waltz fd_ballet fd_util)
$(call run-unit-test,test_grpc_codec)
$(call make-unit-test,test_grpc_client,test_grpc_client,fd_waltz fd_ballet fd_util,$(OPENSSL_LIBS))
$(call run-unit-test,test_grpc_client)

$(call add-hdrs,fd_grpc_client.h)
$(call add-objs,fd_grpc_client,fd_waltz)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_grpc_codec,fuzz_grpc_codec,fd_waltz fd_ballet fd_util)
$(call make-fuzz-test,fuzz_grpc_h2_gen_req_hdr,fuzz_grpc_h2_gen_req_hdr,fd_waltz fd_ballet fd_util)
$(call make-fuzz-test,fuzz_grpc_client,fuzz_grpc_client,fd_waltz fd_ballet fd_util,$(OPENSSL_LIBS))
endif
