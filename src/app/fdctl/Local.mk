ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_X86
ifdef FD_HAS_DOUBLE
$(call make-lib,fd_fdctl)
$(call add-objs,main config security utility run keygen monitor/monitor monitor/helper configure/configure configure/large_pages configure/sysctl configure/shmem configure/xdp configure/xdp_leftover configure/ethtool configure/workspace_leftover configure/workspace,fd_fdctl)
$(call make-bin,fdctl,main1,fd_fdctl fd_frank fd_disco fd_ballet fd_tango fd_util fd_quic solana_validator_fd)
$(OBJDIR)/bin/fdctl: src/app/fdctl/config/default.toml
endif
endif
endif
endif
