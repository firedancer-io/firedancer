ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
ifdef FD_HAS_INT128
$(call add-hdrs,fd_poh.h)
$(call add-objs,fd_pohi_tile fd_poh,fd_discof)
endif
endif
endif
