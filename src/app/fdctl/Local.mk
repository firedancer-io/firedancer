ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_X86
ifdef FD_HAS_DOUBLE
$(call make-lib,fd_fdctl)
$(call add-objs,main1 config security utility run keygen monitor/monitor monitor/helper configure/configure configure/large_pages configure/sysctl configure/shmem configure/xdp configure/xdp_leftover configure/ethtool configure/workspace_leftover configure/workspace,fd_fdctl)
$(call make-bin,fdctl,main,fd_fdctl fd_frank fd_disco fd_ballet fd_tango fd_util fd_quic solana_validator_fd)
$(OBJDIR)/obj/app/fdctl/configure/xdp.o: src/tango/xdp/fd_xdp_redirect_prog.o
$(OBJDIR)/obj/app/fdctl/config.o: src/app/fdctl/config/default.toml
endif
endif
endif
endif
