ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_gossip.h)
$(call add-objs,fd_gossip,fd_flamenco)
$(call make-bin,fd_gossip_spy,fd_gossip_spy,fd_flamenco fd_ballet fd_funk fd_util)
endif
endif
