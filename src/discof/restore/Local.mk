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
$(call add-objs,utils/fd_ssmsg,fd_discof)
$(call add-objs,utils/fd_snapshot_parser,fd_discof)
endif
$(call add-objs,utils/fd_ssping,fd_discof)
$(call add-objs,utils/fd_sshttp,fd_discof)
$(call add-objs,utils/fd_ssarchive,fd_discof)
