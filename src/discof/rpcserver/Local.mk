include src/app/fdctl/with-version.mk
$(info Using RPC_VERSION=$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH))
CFLAGS += -DRPC_VERSION='"$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH)"'

ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-hdrs,fd_rpc_service.h)
$(call add-objs,fd_block_to_json fd_methods fd_rpc_service fd_webserver json_lex keywords fd_stub_to_json base_enc fd_rpcserv_tile fd_rpc_history,fd_discof)

$(call make-unit-test,test_rpc_keywords,test_keywords keywords,fd_util)
#$(call make-fuzz-test,fuzz_json_lex,fuzz_json_lex json_lex,fd_util)
endif
endif
