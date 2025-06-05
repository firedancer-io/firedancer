$(call add-hdrs,fd_archiver.h)
ifdef FD_HAS_SSE
$(call add-objs,fd_archiver_feeder,fd_disco)
$(call add-objs,fd_archiver_writer,fd_disco)
$(call add-objs,fd_archiver_playback,fd_disco)
endif
