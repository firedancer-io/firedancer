ifdef FD_HAS_LIBMICROHTTP
$(call add-objs, fd_rpc_service keywords fd_block_to_json, fd_flamenco)
$(call add-hdrs,fd_rpc_service.h)
endif
$(call make-unit-test,test_rpc_keywords,test_keywords keywords,)
