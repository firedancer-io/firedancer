ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
CFLAGS+='-DFIREDANCER_VERSION="$(FIREDANCER_VERSION_MAJOR).$(FIREDANCER_VERSION_MINOR).$(FIREDANCER_VERSION_PATCH)"'

$(call make-bin,fd_rpcserver,main,fd_flamenco fd_reedsol fd_disco fd_ballet fd_funk fd_shred fd_tango fd_choreo fd_waltz fd_util, $(SECP256K1_LIBS))
endif
endif
