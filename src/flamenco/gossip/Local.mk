ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call add-hdrs,fd_gossip.h fd_contact_info.h)
$(call add-hdrs,fd_gossip_types.h)
$(call add-objs,fd_gossip fd_contact_info,fd_flamenco)
$(call make-bin,fd_gossip_spy,fd_gossip_spy,fd_flamenco fd_ballet fd_util)

$(call make-unit-test,test_contact_info,test_contact_info,fd_flamenco fd_ballet fd_util)
endif
endif
