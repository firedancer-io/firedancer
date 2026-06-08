$(call add-hdrs,fd_finality_tracker.h fd_parent_ready_tracker.h fd_slot_state.h)
$(call add-objs,fd_finality_tracker fd_parent_ready_tracker fd_slot_state,fd_alpenglow)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_finality_tracker,test_finality_tracker,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_parent_ready_tracker,test_parent_ready_tracker,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_slot_state,test_slot_state,fd_alpenglow fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_finality_tracker)
$(call run-unit-test,test_parent_ready_tracker)
$(call run-unit-test,test_slot_state)
endif
