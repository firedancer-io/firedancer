ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_replay.h fd_store.h fd_pending_slots.h)
$(call add-objs,fd_replay fd_store fd_pending_slots,fd_disco)
endif
endif
endif
