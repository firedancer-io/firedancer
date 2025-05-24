ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_plugin_tile,fd_disco,fd_flamenco)
endif
endif
