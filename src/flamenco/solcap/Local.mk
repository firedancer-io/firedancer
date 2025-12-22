$(call add-hdrs,fd_pkt_writer.h)

$(call add-hdrs,fd_pkt_w_tango.h)
$(call add-objs,fd_pkt_w_tango,fd_flamenco)

ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_pkt_w_pcapng.h)
$(call add-objs,fd_pkt_w_pcapng,fd_flamenco)
endif
