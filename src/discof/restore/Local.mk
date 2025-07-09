ifdef FD_HAS_SSE
$(call add-objs,fd_snaprd_tile,fd_discof)
ifdef FD_HAS_ZSTD
$(call add-objs,fd_snapdc_tile,fd_discof)
endif
ifdef FD_HAS_INT128
$(call add-objs,fd_snapin_tile,fd_discof)
endif
endif
ifdef FD_HAS_INT128
$(call add-objs,utils/fd_snapshot_messages,fd_discof)
$(call add-objs,utils/fd_snapshot_parser,fd_discof)
endif
$(call add-objs,utils/fd_snapshot_reader,fd_discof)
$(call add-objs,utils/fd_snapshot_file,fd_discof)
$(call add-objs,utils/fd_snapshot_archive,fd_discof)
$(call add-objs,utils/fd_snapshot_httpdl,fd_discof)
$(call add-objs,utils/fd_snapshot_peers_manager,fd_discof)
$(call add-objs,utils/fd_icmp_ping,fd_discof)
