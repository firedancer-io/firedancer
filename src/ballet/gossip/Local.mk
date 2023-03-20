$(call add-hdrs,fd_gossip_msg.h, fd_gossip_crds.h fd_gossip_pretty_print.h fd_gossip_validation.h fd_gossip_vector_utils.h )
$(call add-objs,fd_gossip_msg_decode fd_gossip_crds_decode fd_gossip_msg_encode fd_gossip_crds_encode fd_gossip_pretty_print,fd_ballet)
$(call make-unit-test,test_gossip_parsing,test_gossip_parsing,fd_ballet fd_util)
$(call make-unit-test,test_gossip_encoding,test_gossip_encoding,fd_ballet fd_util)
