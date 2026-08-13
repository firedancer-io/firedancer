ifdef FD_HAS_BLST
$(call add-hdrs,ag_slot.h)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_slot,test_slot,fd_util)
$(call run-unit-test,test_slot)
endif
endif
