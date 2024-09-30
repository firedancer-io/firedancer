ifdef FD_HAS_INT128
CFLAGS+='-DFIREDANCER_VERSION="$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH)"'

$(call make-bin,fd_rpcserver,main fd_block_to_json fd_methods fd_rpc_service fd_webserver json_lex keywords fd_stub_to_json base_enc,fd_flamenco fd_ballet fd_reedsol fd_disco fd_funk fd_shred fd_tango fd_choreo fd_waltz fd_util, $(SECP256K1_LIBS))
endif

$(call make-unit-test,test_rpc_keywords,test_keywords keywords,fd_util)
$(call make-fuzz-test,fuzz_json_lex,fuzz_json_lex json_lex,fd_util)
