$(call add-hdrs,fd_solcap_writer.h)

$(call add-hdrs,fd_pkt_writer.h)

$(call add-hdrs,fd_pkt_w_tango.h)
$(call add-objs,fd_pkt_w_tango,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_pkt_w_pcapng.h)
$(call add-objs,fd_pkt_w_pcapng,fd_flamenco)
$(call make-unit-test,test_solcap_writer,test_solcap_writer,fd_flamenco fd_tango fd_util)
endif
