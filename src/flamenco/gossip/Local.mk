ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_gossip.h)
$(call add-objs,fd_gossip,fd_flamenco)
$(call make-bin,gossip-bench,fd_gossip_bench,fd_flamenco fd_disco fd_ballet fd_util)
endif
endif
