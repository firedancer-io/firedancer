ifdef FD_HAS_INT128
$(call add-hdrs,fd_bincode.h fd_types.h fd_types_custom.h)
$(call add-objs,fd_types,fd_flamenco)
endif
