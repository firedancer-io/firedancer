$(call add-hdrs,fd_solcap_proto.h fd_solcap_writer.h fd_solcap_reader.h)
ifdef FD_HAS_INT128
ifdef FD_HAS_HOSTED
$(call add-objs,fd_solcap_writer fd_solcap_reader fd_solcap.pb,fd_flamenco)
$(call make-bin,fd_solcap_diff,fd_solcap_diff,fd_flamenco fd_ballet fd_util)
$(call make-bin,fd_solcap_import,fd_solcap_import,fd_flamenco fd_ballet fd_util)
$(call make-bin,fd_solcap_yaml,fd_solcap_yaml,fd_flamenco fd_ballet fd_util)
else
$(call add-objs,fd_solcap_writer_stub,fd_flamenco)
endif
endif
