$(call add-hdrs,fd_alut.h)

$(call add-hdrs,fd_accdb_svm.h)
$(call add-objs,fd_accdb_svm,fd_flamenco)

$(call add-hdrs,fd_blockhashes.h)
$(call add-objs,fd_blockhashes,fd_flamenco)

$(call add-objs,fd_core_bpf_migration,fd_flamenco)

$(call add-hdrs,fd_executor.h)
$(call add-objs,fd_executor,fd_flamenco)

$(call add-hdrs,fd_hashes.h)
$(call add-objs,fd_hashes,fd_flamenco)
ifdef FD_HAS_ATOMIC
$(call make-unit-test,test_hashes,test_hashes,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_hashes)
endif

$(call add-hdrs,fd_pubkey_utils.h)
$(call add-objs,fd_pubkey_utils,fd_flamenco)

$(call add-hdrs,fd_slot_params.h)
ifdef FD_HAS_INT128
$(call add-objs,fd_slot_params,fd_flamenco)
$(call make-unit-test,test_slot_params,test_slot_params,fd_flamenco fd_funk fd_ballet fd_util)
$(call run-unit-test,test_slot_params)
endif

ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_txncache_shmem.h fd_txncache.h)
$(call add-objs,fd_txncache_shmem fd_txncache,fd_flamenco)
$(call add-hdrs,fd_cost_tracker.h)
$(call add-objs,fd_cost_tracker,fd_flamenco)
$(call make-unit-test,test_cost_tracker,test_cost_tracker,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_cost_tracker)
endif

$(call add-hdrs,fd_compute_budget_details.h)
$(call add-objs,fd_compute_budget_details,fd_flamenco)

$(call add-hdrs,fd_borrowed_account.h)
$(call add-objs,fd_borrowed_account,fd_flamenco)

ifdef FD_HAS_ATOMIC
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_bundle_exec,test_bundle_exec,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_bundle_exec)

$(call make-unit-test,test_programdata_delayvis,test_programdata_delayvis,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_programdata_delayvis)
endif
$(call make-unit-test,test_runtime_alut,test_runtime_alut,fd_flamenco_test fd_flamenco fd_tango fd_ballet fd_util fd_disco)
$(call run-unit-test,test_runtime_alut)
endif

ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_bank.h)
$(call add-objs,fd_bank,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_bank,test_bank,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_bank)
endif
endif

ifdef FD_HAS_HOSTED
$(call make-unit-test,test_txncache,test_txncache,fd_flamenco fd_ballet fd_util)
ifdef FD_HAS_ATOMIC
$(call make-fuzz-test,fuzz_txncache_fork_graph,fuzz_txncache_fork_graph,fd_flamenco fd_ballet fd_util)
endif
endif

ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_runtime.h fd_runtime_err.h fd_runtime_const.h fd_runtime_stack.h fd_runtime_helpers.h)
$(call add-objs,fd_runtime,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_lamports_per_byte_feature_gates,test_lamports_per_byte_feature_gates,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_lamports_per_byte_feature_gates)
$(call make-unit-test,test_vat_refresh_vote_accounts,test_vat_refresh_vote_accounts,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_vat_refresh_vote_accounts)
$(call make-unit-test,test_instr_acct_bounds,test_instr_acct_bounds,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_instr_acct_bounds)
$(call make-unit-test,test_define_ltds_fee_only_semantics,test_define_ltds_fee_only_semantics,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_define_ltds_fee_only_semantics)
$(call make-unit-test,test_accounts_resize_delta,tests/test_accounts_resize_delta,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_accounts_resize_delta)
$(call make-unit-test,test_fee_reward,tests/test_fee_reward,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_fee_reward)
ifdef FD_HAS_DOUBLE
$(call make-unit-test,test_inflation_rewards,tests/test_inflation_rewards,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_inflation_rewards)
endif
$(call make-unit-test,test_fee_calculator,tests/test_fee_calculator,fd_flamenco_test fd_flamenco fd_ballet fd_util fd_disco)
$(call run-unit-test,test_fee_calculator)
$(call make-unit-test,test_cost_model,tests/test_cost_model,fd_flamenco_test fd_flamenco fd_ballet fd_util fd_disco)
$(call run-unit-test,test_cost_model)
$(call make-unit-test,test_feature_activation,tests/test_feature_activation,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_feature_activation)
endif
endif

$(call add-hdrs,fd_system_ids.h)
$(call add-objs,fd_system_ids,fd_flamenco)
$(call make-unit-test,test_system_ids,test_system_ids,fd_flamenco fd_util fd_ballet)
$(call run-unit-test,test_system_ids)

ifdef FD_HAS_ATOMIC

ifdef FD_HAS_HOSTED
# TODO: Flakes
# $(call run-unit-test,test_txncache)
endif
endif
