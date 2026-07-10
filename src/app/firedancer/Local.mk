ifdef FD_HAS_HOSTED
ifdef FD_HAS_THREADS
ifdef FD_HAS_ALLOCA
ifdef FD_HAS_DOUBLE
ifdef FD_HAS_ZSTD

$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/default.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/testnet.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/devnet.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/mainnet.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/testnet-jito.toml
$(OBJDIR)/obj/app/firedancer/config.o: src/app/firedancer/config/mainnet-jito.toml

.PHONY: firedancer

# firedancer core
$(call add-objs,topology,fd_firedancer)
$(call add-objs,config,fd_firedancer)
$(call add-objs,callbacks,fd_firedancer)

# commands
$(call add-objs,commands/add_authorized_voter,fd_firedancer)
$(call add-objs,commands/shred_version,fd_firedancer)
$(call add-objs,commands/set_identity,fd_firedancer)
$(call add-objs,commands/get_identity,fd_firedancer)
$(call add-objs,commands/monitor_gossip/monitor_gossip commands/monitor_gossip/gossip_diag,fd_firedancer)

ifdef FD_HAS_SSE
# ifdef FD_HAS_BLST -- will be a required dependency soon
ifdef FD_HAS_S2NBIGNUM
$(call make-bin,firedancer,main,fd_firedancer fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_quic fd_tls fd_reedsol fd_waltz fd_tango fd_ballet fd_util,$(OPENSSL_LIBS))
endif
# endif
endif

else
$(warning firedancer build disabled due to lack of zstd)
endif
endif
endif
endif
endif
