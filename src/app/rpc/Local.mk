ifdef FD_HAS_LIBMICROHTTP
$(call make-bin,fd_rpc,main keywords fd_block_to_json,fd_webserver fd_flamenco fd_ballet fd_funk fd_util libmicrohttp)
endif
$(call make-unit-test,test_keywords,test_keywords keywords,)
