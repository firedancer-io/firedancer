ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call make-bin,fd_rpcserver,main,fd_disco fd_flamenco fd_reedsol fd_ballet fd_funk fd_tango fd_choreo fd_waltz fd_util, $(SECP256K1_LIBS))
endif
endif
