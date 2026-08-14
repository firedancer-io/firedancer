ifdef FD_HAS_BLST

$(call add-hdrs,ag_votor_base.h ag_aggsig.h ag_aggsig_serde.h ag_vote.h ag_vote_serde.h ag_epoch_info.h ag_cert.h ag_cert_serde.h ag_pool.h ag_slot_state.h ag_finality_tracker.h ag_parent_ready_tracker.h)
$(call add-objs,ag_aggsig ag_aggsig_serde ag_vote ag_vote_serde ag_epoch_info ag_cert ag_cert_serde ag_pool ag_slot_state ag_finality_tracker ag_parent_ready_tracker,fd_choreo)

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_ag_votor_base,test_ag_votor_base,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_aggsig,test_ag_aggsig,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_vote,test_ag_vote,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_epoch_info,test_ag_epoch_info,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_cert,test_ag_cert,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_pool,test_ag_pool,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_slot_state,test_ag_slot_state,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_finality_tracker,test_ag_finality_tracker,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_ag_parent_ready_tracker,test_ag_parent_ready_tracker,fd_choreo fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_ag_votor_base)
$(call run-unit-test,test_ag_aggsig)
$(call run-unit-test,test_ag_vote)
$(call run-unit-test,test_ag_epoch_info)
$(call run-unit-test,test_ag_cert)
$(call run-unit-test,test_ag_pool)
$(call run-unit-test,test_ag_slot_state)
$(call run-unit-test,test_ag_finality_tracker)
$(call run-unit-test,test_ag_parent_ready_tracker)
endif

else

# Alpenglow is only a valid protocol with BLS, so the whole subtree is a
# no-op without libblst rather than being stubbed out source by source.

$(warning alpenglow disabled due to lack of libblst)

endif
