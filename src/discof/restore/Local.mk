$(call add-objs,fd_snaprd_tile,fd_discof)
ifdef FD_HAS_ZSTD
$(call add-objs,fd_unzstd_tile,fd_discof)
endif
ifdef FD_HAS_INT128
$(call add-objs,fd_snapin_tile,fd_discof)
$(call add-objs,fd_actalc_tile,fd_discof)
endif
$(call add-objs,fd_actidx_tile,fd_discof)
$(call add-objs,fd_httpdl_tile,fd_discof)
$(call add-objs,stream/fd_stream_writer,fd_discof)
$(call add-objs,stream/fd_event_map,fd_discof)
$(call add-objs,stream/fd_stream_ctx,fd_discof)
