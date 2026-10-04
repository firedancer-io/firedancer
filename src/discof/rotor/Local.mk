$(call add-hdrs,fd_rotor_tile.h)
ifdef FD_HAS_HOSTED
$(call add-objs,fd_rotor_tile,fd_discof)
endif
