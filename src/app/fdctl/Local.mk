ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_X86
ifdef FD_HAS_DOUBLE
$(call make-bin,fdctl,main config security utility run monitor configure/configure configure/large_pages configure/shmem configure/netns configure/xdp configure/xdp_leftover configure/ethtool configure/workspace_leftover configure/workspace configure/frank,fd_frank fd_disco fd_ballet fd_tango fd_util fd_quic)
endif
endif
endif
endif
