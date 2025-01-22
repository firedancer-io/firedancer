ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_gossip.h)
$(call add-objs,fd_gossip,fd_flamenco)
endif
endif
