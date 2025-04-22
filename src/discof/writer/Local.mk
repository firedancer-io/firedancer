ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_writer_tile,fd_discof)
endif
endif
