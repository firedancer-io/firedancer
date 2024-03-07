ifdef FD_HAS_INT128
$(call add-hdrs,fd_gossip.h)
$(call add-objs,fd_gossip,fd_flamenco)
$(call make-bin,fd_gossip_spy,fd_gossip_spy,fd_ballet fd_funk fd_util fd_flamenco)
$(call make-unit-test,test_gossip,test_gossip,fd_flamenco fd_ballet fd_util)
endif
