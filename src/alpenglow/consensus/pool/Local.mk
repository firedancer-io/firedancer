$(call add-hdrs,ag_finality_tracker.h ag_parent_ready_tracker.h ag_slot_state.h)
$(call add-objs,ag_finality_tracker ag_parent_ready_tracker ag_slot_state,ag_alpenglow)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_finality_tracker,test_finality_tracker,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_parent_ready_tracker,test_parent_ready_tracker,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_slot_state,test_slot_state,ag_alpenglow fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_finality_tracker)
$(call run-unit-test,test_parent_ready_tracker)
$(call run-unit-test,test_slot_state)
endif
