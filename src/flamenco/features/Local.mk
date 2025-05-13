ifdef FD_HAS_INT128
$(call add-hdrs,fd_features.h fd_features_generated.h)
$(call add-objs,fd_features fd_features_generated,fd_flamenco)
endif
