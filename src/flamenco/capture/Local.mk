ifdef FD_HAS_INT128
ifdef FD_HAS_HOSTED
$(call add-objs,fd_solcap_writer fd_solcap.pb,fd_flamenco)
$(call add-hdrs,fd_solcap_proto.h fd_solcap_writer.h)
endif
endif
