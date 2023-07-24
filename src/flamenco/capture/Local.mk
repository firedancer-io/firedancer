$(call add-hdrs,fd_solcap_proto.h fd_solcap_writer.h)
$(call add-objs,fd_solcap_writer,fd_flamenco)
$(call make-bin,fd_solcap_yaml,fd_solcap_yaml,fd_flamenco fd_ballet fd_util)
