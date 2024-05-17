ifdef FD_WITH_RPCSERVER

LDFLAGS+=-Wl,--push-state,-Bstatic -lmicrohttpd -Wl,--pop-state -lgmp

$(call make-bin,fd_rpcserver,main fd_block_to_json fd_methods fd_quickstring fd_rpc_service fd_webserver json_lex keywords,fd_flamenco fd_ballet fd_reedsol fd_disco fd_funk fd_shred fd_tango fd_choreo fd_waltz fd_util, $(SECP256K1_LIBS))

$(call make-unit-test,test_rpc_keywords,test_keywords keywords,fd_util)
$(call fuzz-test,fuzz_json_lex,fuzz_json_lex,fd_util)

endif
