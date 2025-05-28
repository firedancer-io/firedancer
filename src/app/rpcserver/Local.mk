ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call make-bin,fd_rpcserver,main,fd_discof fd_disco fd_flamenco fd_reedsol fd_funk fd_tango fd_choreo fd_waltz fd_ballet fd_util,$(SECP256K1_LIBS))
endif
endif
endif
