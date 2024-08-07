ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
ifdef FD_HAS_ZSTD
$(call add-hdrs,fd_store.h fd_pending_slots.h fd_trusted_slots.h)
$(call add-objs,fd_store fd_pending_slots fd_trusted_slots,fd_disco)
$(call make-unit-test,test_trusted_slots,test_trusted_slots,fd_disco fd_util)
endif
endif
endif
