#include "fd_features.h"
#include "fd_runtime.h"
void fd_enable_testnet(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->secp256k1_program_enabled = 39404256; // secp256k1 program
  f->deprecate_rewards_sysvar = 39404256; // deprecate unused rewards sysvar
  f->spl_token_v2_multisig_fix = 39836256; // spl-token multisig fix
  f->no_overflow_rent_distribution = 47612256; // no overflow rent distribution
  f->pico_inflation = 49772256; // pico inflation
  f->filter_stake_delegation_accounts = 54092257; // filter stake_delegation_accounts #14062
  f->spl_token_v2_self_transfer_fix = 64028256; // spl-token self-transfer fix
  f->check_init_vote_data = 67052260; // check initialized Vote data
  f->require_custodian_for_locked_stake_authorize = 67052260; // require custodian to authorize withdrawer change for locked stake
  f->system_transfer_zero_check = 84332260; // perform all checks for transfers of 0 lamports
  f->merge_nonce_error_into_system_error = 86060263; // merge NonceError into SystemError
  f->secp256k1_recover_syscall_enabled = 86060263; // secp256k1_recover syscall
  f->dedupe_config_program_signers = 86060263; // dedupe config program signers
  f->libsecp256k1_0_5_upgrade_enabled = 86060263; // upgrade libsecp256k1 to v0.5.0
  f->spl_token_v2_set_authority_fix = 89084265; // spl-token set_authority fix
  f->vote_stake_checked_instructions = 89516256; // vote/state program checked instructions #18345
  f->verify_tx_signatures_len = 94700260; // prohibit extra transaction signatures
  f->demote_program_write_locks = 96860257; // demote program write locks to readonly, except when upgradeable loader present #19593 #20265
  f->send_to_tpu_vote_port = 96860257; // send votes to the tpu vote port
  f->reduce_required_deploy_balance = 96860257; // reduce required payer balance for program deploys
  f->stakes_remove_delegation_if_inactive = 96860257; // remove delegations from stakes cache when inactive
  f->stake_program_advance_activating_credits_observed = 96860257; // Enable advancing credits observed for activation epoch #19309
  f->stake_merge_with_unmatched_credits_observed = 96860257; // allow merging active stakes with unmatched credits_observed #18985
  f->optimize_epoch_boundary_updates = 99452256; // optimize epoch boundary updates
  f->rent_for_sysvars = 100748256; // collect rent from accounts owned by sysvars
  f->add_compute_budget_program = 105068256; // Add compute_budget_program
  f->remove_native_loader = 106796256; // remove support for the native loader
  f->ed25519_program_enabled = 112412257; // enable builtin ed25519 signature verify program
  f->sol_log_data_syscall_enabled = 112412257; // enable sol_log_data syscall
  f->return_data_syscall_enabled = 112412257; // enable sol_{set,get}_return_data syscall
  f->spl_token_v3_3_0_release = 112844260; // spl-token v3.3.0 release
  f->reject_non_rent_exempt_vote_withdraws = 113708264; // fail vote withdraw instructions which leave the account non-rent-exempt
  f->reject_empty_instruction_without_program = 113708264; // fail instructions which have native_loader as program_id directly
  f->max_tx_account_locks = 113708264; // enforce max number of locked accounts per transaction
  f->evict_invalid_stakes_cache_entries = 113708264; // evict invalid stakes cache entries on epoch boundaries
  f->instructions_sysvar_owned_by_sysvar = 113708264; // fix owner for instructions sysvar
  f->disable_fee_calculator = 114140256; // deprecate fee calculator
  f->prevent_calling_precompiles_as_programs = 114140256; // prevent calling precompiles as programs
  f->nonce_must_be_writable = 114140256; // nonce must be writable
  f->leave_nonce_on_success = 114140256; // leave nonce as is on success
  f->spl_associated_token_account_v1_0_4 = 122348260; // SPL Associated Token Account Program release version 1.0.4, tied to token 3.3.0 #22648
  f->vote_withdraw_authority_may_change_authorized_voter = 124076256; // vote account withdraw authority may change the authorized voter #22521
  f->update_syscall_base_costs = 124508260; // update syscall base costs
  f->disable_bpf_deprecated_load_instructions = 124508260; // disable ldabs* and ldind* SBF instructions
  f->disable_bpf_unresolved_symbols_at_runtime = 124508260; // disable reporting of unresolved SBF symbols at runtime
  f->tx_wide_compute_cap = 124508260; // transaction wide compute cap
  f->requestable_heap_size = 124508260; // Requestable heap frame size
  f->add_get_processed_sibling_instruction_syscall = 124508260; // add add_get_processed_sibling_instruction_syscall
  f->do_support_realloc = 125804256; // support account data reallocation
  f->require_rent_exempt_accounts = 125804256; // require all new transaction accounts with data to be rent-exempt
  f->versioned_tx_message_enabled = 127100256; // enable versioned transaction message processing
  f->filter_votes_outside_slot_hashes = 130556260; // filter vote slots older than the slot hashes history
  f->warp_timestamp_with_a_vengeance = 135308256; // warp timestamp again, adjust bounding to 150% slow #25666
  f->default_units_per_instruction = 135308256; // Default max tx-wide compute units calculated per instruction
  f->fixed_memcpy_nonoverlapping_check = 136172256; // use correct check for nonoverlapping regions in memcpy syscall
  f->add_shred_type_to_shred_seed = 136172256; // add shred-type to shred seed #25556
  f->nonce_must_be_advanceable = 137036260; // durable nonces must be advanceable
  f->enable_durable_nonce = 137036260; // enable durable nonce #25744
  f->separate_nonce_from_blockhash = 137036260; // separate durable nonce and blockhash domains #25744
  f->nonce_must_be_authorized = 137036260; // nonce must be authorized
  f->executables_incur_cpi_data_cost = 137468257; // Executables incur CPI data costs
  f->add_set_compute_unit_price_ix = 137900256; // add compute budget ix for setting a compute unit price
  f->quick_bail_on_panic = 138332256; // quick bail on panic
  f->record_instruction_in_transaction_context_push = 138764256; // move the CPI stack overflow check to the end of push
  f->limit_secp256k1_recovery_id = 138764256; // limit secp256k1 recovery id
  f->check_physical_overlapping = 139196256; // check physical overlapping regions
  f->syscall_saturated_math = 140060257; // syscalls use saturated math
  f->reject_vote_account_close_unless_zero_credit_epoch = 140924260; // fail vote account withdraw to 0 unless account earned 0 credits in last completed epoch
  f->spl_associated_token_account_v1_1_0 = 143084256; // SPL Associated Token Account Program version 1.1.0 release #24741
  f->spl_token_v3_4_0 = 143084256; // SPL Token Program version 3.4.0 release #24740
  f->vote_authorize_with_seed = 144380257; // An instruction you can use to change a vote accounts authority when the current authority is a derived key #25860
  f->include_account_index_in_rent_error = 144812257; // include account index in rent tx error #25190
  f->require_static_program_ids_in_transaction = 144812257; // require static program ids in versioned transactions
  f->preserve_rent_epoch_for_rent_exempt_accounts = 145676256; // preserve rent epoch for rent exempt accounts #26479
  f->prevent_crediting_accounts_that_end_rent_paying = 146972256; // prevent crediting rent paying accounts #26606
  f->disable_deprecated_loader = 158204260; // disable the deprecated BPF loader
  f->check_syscall_outputs_do_not_overlap = 165980260; // check syscall outputs do_not overlap #28600
  f->bank_transaction_count_fix = 168572256; // fixes Bank::transaction_count to include all committed transactions, not just successful ones
  f->reject_callx_r10 = 195356264; // Reject bpf callx r10 instructions
  f->stake_deactivate_delinquent_instruction = 195356264; // enable the deactivate delinquent stake instruction #23932
  f->libsecp256k1_fail_on_bad_count2 = 195356264; // fail libsec256k1_verify if count appears wrong
  f->fix_recent_blockhashes = 195356264; // stop adding hashes for skipped slots to recent blockhashes
  f->move_serialized_len_ptr_in_cpi = 195356264; // cpi ignore serialized_len_ptr #29592
  f->disable_deploy_of_alloc_free_syscall = 195356264; // disable new deployments of deprecated sol_alloc_free_ syscall
  f->enable_early_verification_of_account_modifications = 195356264; // enable early verification of account modifications #25899
  f->error_on_syscall_bpf_function_hash_collisions = 195356264; // error on bpf function hash collisions
  f->compact_vote_state_updates = 195356264; // Compact vote state updates to lower block size
  f->use_default_units_in_fee_calculation = 195356264; // use default units per instruction in fee calculation #26785
  f->increase_tx_account_lock_limit = 195356264; // increase tx account lock limit to 128 #27241
  f->cap_bpf_program_instruction_accounts = 195356264; // enforce max number of accounts per bpf program instruction #26628
  f->credits_auto_rewind = 195356264; // Auto rewind stake's credits_observed if (accidental) vote recreation is detected #22546
  f->on_load_preserve_rent_epoch_for_rent_exempt_accounts = 195356264; // on bank load account, do not try to fix up rent_epoch #28541
  f->vote_state_update_credit_per_dequeue = 195356264; // Calculate vote credits for VoteStateUpdate per vote dequeue to match credit awards for Vote instruction
  f->disable_rehash_for_rent_epoch = 195356264; // on accounts hash calculation, do not try to rehash accounts #28934
  f->stake_split_uses_rent_sysvar = 195356264; // stake split instruction uses rent sysvar
  f->allow_votes_to_directly_update_vote_state = 195356264; // enable direct vote state update
  f->vote_state_update_root_fix = 195356264; // fix root in vote state updates #27361
  f->loosen_cpi_size_restriction = 195356264; // loosen cpi size restrictions #26641
  f->check_slice_translation_size = 195356264; // check size when translating slices
  f->add_get_minimum_delegation_instruction_to_stake_program = 195356264; // add GetMinimumDelegation instruction to stake program
  f->stake_allow_zero_undelegated_amount = 195356264; // Allow zero-lamport undelegated amount for initialized stakes #24670
  f->drop_redundant_turbine_path = 196220264; // drop redundant turbine path
  f->update_rewards_from_cached_accounts = 197516256; // update rewards from cached accounts
  f->commission_updates_only_allowed_in_first_half_of_epoch = 197948256; // validator commission updates are only allowed in the first half of an epoch #29362
  f->disable_builtin_loader_ownership_chains = 199244256; // disable builtin loader ownership chains #29956
  f->stake_raise_minimum_delegation_to_1_sol = 199676256; // Raise minimum stake delegation to 1.0 SOL #24357
  f->clean_up_delegation_errors = 201404260; // Return InsufficientDelegation instead of InsufficientFunds or InsufficientStake where applicable #31206
  f->limit_max_instruction_trace_length = 203996256; // limit max instruction trace length #27939
  f->switch_to_new_elf_parser = 204428256; // switch to new ELF parser #30497
  f->cap_accounts_data_allocations_per_transaction = 205724256; // cap accounts data allocations per transaction #27375
  f->enable_alt_bn128_syscall = 206156264; // add alt_bn128 syscalls #27961
  f->enable_bpf_loader_extend_program_ix = 207020260; // enable bpf upgradeable loader ExtendProgram instruction #25234
  f->account_hash_ignore_slot = 207452256; // ignore slot when calculating an account hash #28420
  f->epoch_accounts_hash = 207884256; // enable epoch accounts hash calculation #27539
  f->delay_visibility_of_program_deployment = 208316256; // delay visibility of program upgrades #30085
  f->enable_program_redeployment_cooldown = 208316256; // enable program redeployment cooldown #29135
  f->curve25519_syscall_enabled = 208748256; // enable curve25519 syscalls
  f->cap_transaction_accounts_data_size = 209180256; // cap transaction accounts data size up to a limit #27839
  f->add_set_tx_loaded_accounts_data_size_instruction = 210044260; // add compute budget instruction for setting account data size per transaction #30366
  f->update_hashes_per_tick = 210476260; // Update desired hashes per tick on epoch boundary
  f->remove_deprecated_request_unit_ix = 210908260; // remove support for RequestUnitsDeprecated instruction #27500
  f->prevent_rent_paying_rent_recipients = 211340260; // prevent recipients of rent rewards from ending in rent-paying state #30151
  f->checked_arithmetic_in_fee_validation = 211772256; // checked arithmetic in fee validation #31273
  f->round_up_heap_size = 212204260; // round up heap size when calculating heap cost #30679
}
void fd_enable_devnet(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->secp256k1_program_enabled = 5414912; // secp256k1 program
  f->spl_token_v2_multisig_fix = 5414912; // spl-token multisig fix
  f->deprecate_rewards_sysvar = 5414912; // deprecate unused rewards sysvar
  f->no_overflow_rent_distribution = 18144000; // no overflow rent distribution
  f->pico_inflation = 19008000; // pico inflation
  f->filter_stake_delegation_accounts = 25056000; // filter stake_delegation_accounts #14062
  f->full_inflation_mainnet_certusone_vote = 34560000; // community vote allowing Certus One to enable full inflation
  f->spl_token_v2_self_transfer_fix = 37152000; // spl-token self-transfer fix
  f->check_init_vote_data = 41472000; // check initialized Vote data
  f->require_custodian_for_locked_stake_authorize = 41472000; // require custodian to authorize withdrawer change for locked stake
  f->system_transfer_zero_check = 67392000; // perform all checks for transfers of 0 lamports
  f->merge_nonce_error_into_system_error = 70416000; // merge NonceError into SystemError
  f->secp256k1_recover_syscall_enabled = 70416000; // secp256k1_recover syscall
  f->dedupe_config_program_signers = 70416000; // dedupe config program signers
  f->libsecp256k1_0_5_upgrade_enabled = 70416000; // upgrade libsecp256k1 to v0.5.0
  f->spl_token_v2_set_authority_fix = 73872000; // spl-token set_authority fix
  f->vote_stake_checked_instructions = 74304000; // vote/state program checked instructions #18345
  f->verify_tx_signatures_len = 81648000; // prohibit extra transaction signatures
  f->demote_program_write_locks = 85536000; // demote program write locks to readonly, except when upgradeable loader present #19593 #20265
  f->send_to_tpu_vote_port = 85536000; // send votes to the tpu vote port
  f->reduce_required_deploy_balance = 85536000; // reduce required payer balance for program deploys
  f->stakes_remove_delegation_if_inactive = 85536000; // remove delegations from stakes cache when inactive
  f->stake_program_advance_activating_credits_observed = 85536000; // Enable advancing credits observed for activation epoch #19309
  f->stake_merge_with_unmatched_credits_observed = 85536000; // allow merging active stakes with unmatched credits_observed #18985
  f->rent_for_sysvars = 90720000; // collect rent from accounts owned by sysvars
  f->optimize_epoch_boundary_updates = 98496000; // optimize epoch boundary updates
  f->add_compute_budget_program = 99360000; // Add compute_budget_program
  f->remove_native_loader = 101952000; // remove support for the native loader
  f->reject_non_rent_exempt_vote_withdraws = 108864000; // fail vote withdraw instructions which leave the account non-rent-exempt
  f->evict_invalid_stakes_cache_entries = 108864000; // evict invalid stakes cache entries on epoch boundaries
  f->spl_token_v3_3_0_release = 108864000; // spl-token v3.3.0 release
  f->ed25519_program_enabled = 109296004; // enable builtin ed25519 signature verify program
  f->sol_log_data_syscall_enabled = 109296004; // enable sol_log_data syscall
  f->return_data_syscall_enabled = 109296004; // enable sol_{set,get}_return_data syscall
  f->vote_withdraw_authority_may_change_authorized_voter = 123552000; // vote account withdraw authority may change the authorized voter #22521
  f->spl_associated_token_account_v1_0_4 = 126144000; // SPL Associated Token Account Program release version 1.0.4, tied to token 3.3.0 #22648
  f->update_syscall_base_costs = 128304000; // update syscall base costs
  f->fixed_memcpy_nonoverlapping_check = 128304000; // use correct check for nonoverlapping regions in memcpy syscall
  f->disable_bpf_deprecated_load_instructions = 128304000; // disable ldabs* and ldind* SBF instructions
  f->prevent_calling_precompiles_as_programs = 128304000; // prevent calling precompiles as programs
  f->disable_bpf_unresolved_symbols_at_runtime = 128304000; // disable reporting of unresolved SBF symbols at runtime
  f->tx_wide_compute_cap = 128304000; // transaction wide compute cap
  f->do_support_realloc = 128304000; // support account data reallocation
  f->libsecp256k1_fail_on_bad_count = 128304000; // fail libsec256k1_verify if count appears wrong
  f->reject_empty_instruction_without_program = 128304000; // fail instructions which have native_loader as program_id directly
  f->nonce_must_be_writable = 128304000; // nonce must be writable
  f->require_rent_exempt_accounts = 128304000; // require all new transaction accounts with data to be rent-exempt
  f->requestable_heap_size = 128304000; // Requestable heap frame size
  f->add_get_processed_sibling_instruction_syscall = 128304000; // add add_get_processed_sibling_instruction_syscall
  f->leave_nonce_on_success = 128304000; // leave nonce as is on success
  f->max_tx_account_locks = 132192000; // enforce max number of locked accounts per transaction
  f->versioned_tx_message_enabled = 132624000; // enable versioned transaction message processing
  f->instructions_sysvar_owned_by_sysvar = 136944000; // fix owner for instructions sysvar
  f->warp_timestamp_with_a_vengeance = 138672000; // warp timestamp again, adjust bounding to 150% slow #25666
  f->drop_redundant_turbine_path = 139968000; // drop redundant turbine path
  f->add_shred_type_to_shred_seed = 140400000; // add shred-type to shred seed #25556
  f->nonce_must_be_advanceable = 141264000; // durable nonces must be advanceable
  f->enable_durable_nonce = 141264000; // enable durable nonce #25744
  f->separate_nonce_from_blockhash = 141264000; // separate durable nonce and blockhash domains #25744
  f->nonce_must_be_authorized = 141264000; // nonce must be authorized
  f->default_units_per_instruction = 141696000; // Default max tx-wide compute units calculated per instruction
  f->executables_incur_cpi_data_cost = 142560000; // Executables incur CPI data costs
  f->add_set_compute_unit_price_ix = 143424000; // add compute budget ix for setting a compute unit price
  f->quick_bail_on_panic = 144288000; // quick bail on panic
  f->record_instruction_in_transaction_context_push = 144720000; // move the CPI stack overflow check to the end of push
  f->limit_secp256k1_recovery_id = 146016000; // limit secp256k1 recovery id
  f->check_physical_overlapping = 146016000; // check physical overlapping regions
  f->disable_fee_calculator = 146448000; // deprecate fee calculator
  f->reject_vote_account_close_unless_zero_credit_epoch = 147744000; // fail vote account withdraw to 0 unless account earned 0 credits in last completed epoch
  f->syscall_saturated_math = 149472000; // syscalls use saturated math
  f->spl_associated_token_account_v1_1_0 = 151200000; // SPL Associated Token Account Program version 1.1.0 release #24741
  f->spl_token_v3_4_0 = 151200000; // SPL Token Program version 3.4.0 release #24740
  f->vote_authorize_with_seed = 153792000; // An instruction you can use to change a vote accounts authority when the current authority is a derived key #25860
  f->include_account_index_in_rent_error = 154656004; // include account index in rent tx error #25190
  f->require_static_program_ids_in_transaction = 154656004; // require static program ids in versioned transactions
  f->blake3_syscall_enabled = 158976000; // blake3 syscall
  f->preserve_rent_epoch_for_rent_exempt_accounts = 160704000; // preserve rent epoch for rent exempt accounts #26479
  f->prevent_crediting_accounts_that_end_rent_paying = 166752000; // prevent crediting rent paying accounts #26606
  f->increase_tx_account_lock_limit = 166752000; // increase tx account lock limit to 128 #27241
  f->filter_votes_outside_slot_hashes = 167184000; // filter vote slots older than the slot hashes history
  f->disable_deprecated_loader = 174528000; // disable the deprecated BPF loader
  f->stake_deactivate_delinquent_instruction = 182736000; // enable the deactivate delinquent stake instruction #23932
  f->add_get_minimum_delegation_instruction_to_stake_program = 183600000; // add GetMinimumDelegation instruction to stake program
  f->stake_allow_zero_undelegated_amount = 184032000; // Allow zero-lamport undelegated amount for initialized stakes #24670
  f->bank_transaction_count_fix = 184896000; // fixes Bank::transaction_count to include all committed transactions, not just successful ones
  f->credits_auto_rewind = 186624000; // Auto rewind stake's credits_observed if (accidental) vote recreation is detected #22546
  f->libsecp256k1_fail_on_bad_count2 = 187056000; // fail libsec256k1_verify if count appears wrong
  f->vote_state_update_root_fix = 187488000; // fix root in vote state updates #27361
  f->stake_redelegate_instruction = 187920000; // enable the redelegate stake instruction #26294
  f->compact_vote_state_updates = 188784000; // Compact vote state updates to lower block size
  f->check_syscall_outputs_do_not_overlap = 189648000; // check syscall outputs do_not overlap #28600
  f->stake_split_uses_rent_sysvar = 190512000; // stake split instruction uses rent sysvar
  f->vote_state_update_credit_per_dequeue = 191376000; // Calculate vote credits for VoteStateUpdate per vote dequeue to match credit awards for Vote instruction
  f->move_serialized_len_ptr_in_cpi = 192240001; // cpi ignore serialized_len_ptr #29592
  f->allow_votes_to_directly_update_vote_state = 196128000; // enable direct vote state update
  f->fix_recent_blockhashes = 214704000; // stop adding hashes for skipped slots to recent blockhashes
  f->on_load_preserve_rent_epoch_for_rent_exempt_accounts = 214704000; // on bank load account, do not try to fix up rent_epoch #28541
  f->disable_rehash_for_rent_epoch = 214704000; // on accounts hash calculation, do not try to rehash accounts #28934
  f->enable_early_verification_of_account_modifications = 215136000; // enable early verification of account modifications #25899
  f->reject_callx_r10 = 216864000; // Reject bpf callx r10 instructions
  f->error_on_syscall_bpf_function_hash_collisions = 216864000; // error on bpf function hash collisions
  f->cap_bpf_program_instruction_accounts = 218160000; // enforce max number of accounts per bpf program instruction #26628
  f->update_rewards_from_cached_accounts = 218592000; // update rewards from cached accounts
  f->use_default_units_in_fee_calculation = 219888000; // use default units per instruction in fee calculation #26785
  f->disable_builtin_loader_ownership_chains = 222480000; // disable builtin loader ownership chains #29956
  f->check_slice_translation_size = 222912000; // check size when translating slices
  f->disable_deploy_of_alloc_free_syscall = 224208000; // disable new deployments of deprecated sol_alloc_free_ syscall
  f->commission_updates_only_allowed_in_first_half_of_epoch = 224640000; // validator commission updates are only allowed in the first half of an epoch #29362
  f->clean_up_delegation_errors = 225072000; // Return InsufficientDelegation instead of InsufficientFunds or InsufficientStake where applicable #31206
  f->limit_max_instruction_trace_length = 233712000; // limit max instruction trace length #27939
}
void fd_enable_mainnet(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->secp256k1_program_enabled = 41040000; // secp256k1 program
  f->spl_token_v2_multisig_fix = 41040000; // spl-token multisig fix
  f->no_overflow_rent_distribution = 51408000; // no overflow rent distribution
  f->deprecate_rewards_sysvar = 55728001; // deprecate unused rewards sysvar
  f->pico_inflation = 57456000; // pico inflation
  f->filter_stake_delegation_accounts = 57888004; // filter stake_delegation_accounts #14062
  f->full_inflation_mainnet_certusoneenable = 64800004; // full inflation enabled by Certus One
  f->full_inflation_mainnet_certusone_vote = 64800004; // community vote allowing Certus One to enable full inflation
  f->spl_token_v2_self_transfer_fix = 66528004; // spl-token self-transfer fix
  f->warp_timestamp_again = 66528004; // warp timestamp again, adjust bounding to 25% fast 80% slow #15204
  f->check_init_vote_data = 68688000; // check initialized Vote data
  f->require_custodian_for_locked_stake_authorize = 71712000; // require custodian to authorize withdrawer change for locked stake
  f->vote_stake_checked_instructions = 92448000; // vote/state program checked instructions #18345
  f->system_transfer_zero_check = 93312000; // perform all checks for transfers of 0 lamports
  f->spl_token_v2_set_authority_fix = 93312000; // spl-token set_authority fix
  f->demote_program_write_locks = 100656000; // demote program write locks to readonly, except when upgradeable loader present #19593 #20265
  f->send_to_tpu_vote_port = 101088000; // send votes to the tpu vote port
  f->reduce_required_deploy_balance = 102816004; // reduce required payer balance for program deploys
  f->verify_tx_signatures_len = 102816004; // prohibit extra transaction signatures
  f->stake_program_advance_activating_credits_observed = 104112000; // Enable advancing credits observed for activation epoch #19309
  f->stake_merge_with_unmatched_credits_observed = 104112000; // allow merging active stakes with unmatched credits_observed #18985
  f->secp256k1_recover_syscall_enabled = 104976000; // secp256k1_recover syscall
  f->rent_for_sysvars = 104976000; // collect rent from accounts owned by sysvars
  f->optimize_epoch_boundary_updates = 109728000; // optimize epoch boundary updates
  f->dedupe_config_program_signers = 110592000; // dedupe config program signers
  f->libsecp256k1_0_5_upgrade_enabled = 110592000; // upgrade libsecp256k1 to v0.5.0
  f->stakes_remove_delegation_if_inactive = 110592000; // remove delegations from stakes cache when inactive
  f->add_compute_budget_program = 117072004; // Add compute_budget_program
  f->reject_non_rent_exempt_vote_withdraws = 117072004; // fail vote withdraw instructions which leave the account non-rent-exempt
  f->evict_invalid_stakes_cache_entries = 117072004; // evict invalid stakes cache entries on epoch boundaries
  f->spl_token_v3_3_0_release = 117072004; // spl-token v3.3.0 release
  f->remove_native_loader = 117072004; // remove support for the native loader
  f->ed25519_program_enabled = 117936008; // enable builtin ed25519 signature verify program
  f->sol_log_data_syscall_enabled = 117936008; // enable sol_log_data syscall
  f->return_data_syscall_enabled = 117936008; // enable sol_{set,get}_return_data syscall
  f->spl_associated_token_account_v1_0_4 = 130464000; // SPL Associated Token Account Program release version 1.0.4, tied to token 3.3.0 #22648
  f->leave_nonce_on_success = 133056012; // leave nonce as is on success
  f->require_rent_exempt_accounts = 133488000; // require all new transaction accounts with data to be rent-exempt
  f->do_support_realloc = 133920008; // support account data reallocation
  f->add_get_processed_sibling_instruction_syscall = 134352008; // add add_get_processed_sibling_instruction_syscall
  f->tx_wide_compute_cap = 135216004; // transaction wide compute cap
  f->requestable_heap_size = 135216004; // Requestable heap frame size
  f->warp_timestamp_with_a_vengeance = 136512012; // warp timestamp again, adjust bounding to 150% slow #25666
  f->nonce_must_be_writable = 136944004; // nonce must be writable
  f->reject_empty_instruction_without_program = 137376016; // fail instructions which have native_loader as program_id directly
  f->add_shred_type_to_shred_seed = 137376016; // add shred-type to shred seed #25556
  f->fixed_memcpy_nonoverlapping_check = 137808012; // use correct check for nonoverlapping regions in memcpy syscall
  f->nonce_must_be_advanceable = 138240000; // durable nonces must be advanceable
  f->enable_durable_nonce = 138240000; // enable durable nonce #25744
  f->separate_nonce_from_blockhash = 138240000; // separate durable nonce and blockhash domains #25744
  f->nonce_must_be_authorized = 138240000; // nonce must be authorized
  f->update_syscall_base_costs = 138672000; // update syscall base costs
  f->vote_withdraw_authority_may_change_authorized_voter = 138672000; // vote account withdraw authority may change the authorized voter #22521
  f->disable_bpf_deprecated_load_instructions = 139104000; // disable ldabs* and ldind* SBF instructions
  f->disable_bpf_unresolved_symbols_at_runtime = 139104000; // disable reporting of unresolved SBF symbols at runtime
  f->executables_incur_cpi_data_cost = 139536000; // Executables incur CPI data costs
  f->max_tx_account_locks = 140400004; // enforce max number of locked accounts per transaction
  f->quick_bail_on_panic = 140400004; // quick bail on panic
  f->default_units_per_instruction = 141264004; // Default max tx-wide compute units calculated per instruction
  f->record_instruction_in_transaction_context_push = 141696000; // move the CPI stack overflow check to the end of push
  f->add_set_compute_unit_price_ix = 142128000; // add compute budget ix for setting a compute unit price
  f->limit_secp256k1_recovery_id = 142560008; // limit secp256k1 recovery id
  f->check_physical_overlapping = 142560008; // check physical overlapping regions
  f->prevent_calling_precompiles_as_programs = 143424004; // prevent calling precompiles as programs
  f->spl_associated_token_account_v1_1_0 = 144288004; // SPL Associated Token Account Program version 1.1.0 release #24741
  f->spl_token_v3_4_0 = 144288004; // SPL Token Program version 3.4.0 release #24740
  f->disable_fee_calculator = 147744004; // deprecate fee calculator
  f->vote_authorize_with_seed = 148608004; // An instruction you can use to change a vote accounts authority when the current authority is a derived key #25860
  f->syscall_saturated_math = 150768000; // syscalls use saturated math
  f->merge_nonce_error_into_system_error = 151632012; // merge NonceError into SystemError
  f->instructions_sysvar_owned_by_sysvar = 152496000; // fix owner for instructions sysvar
  f->require_static_program_ids_in_transaction = 153360000; // require static program ids in versioned transactions
  f->include_account_index_in_rent_error = 154224000; // include account index in rent tx error #25190
  f->versioned_tx_message_enabled = 154656004; // enable versioned transaction message processing
  f->preserve_rent_epoch_for_rent_exempt_accounts = 156384000; // preserve rent epoch for rent exempt accounts #26479
  f->filter_votes_outside_slot_hashes = 157680012; // filter vote slots older than the slot hashes history
  f->prevent_crediting_accounts_that_end_rent_paying = 161136000; // prevent crediting rent paying accounts #26606
  f->disable_deprecated_loader = 167184008; // disable the deprecated BPF loader
  f->reject_vote_account_close_unless_zero_credit_epoch = 170640000; // fail vote account withdraw to 0 unless account earned 0 credits in last completed epoch
  f->bank_transaction_count_fix = 171072012; // fixes Bank::transaction_count to include all committed transactions, not just successful ones
  f->check_syscall_outputs_do_not_overlap = 174096000; // check syscall outputs do_not overlap #28600
  f->stake_deactivate_delinquent_instruction = 198720004; // enable the deactivate delinquent stake instruction #23932
  f->drop_redundant_turbine_path = 199152000; // drop redundant turbine path
  f->add_get_minimum_delegation_instruction_to_stake_program = 199584000; // add GetMinimumDelegation instruction to stake program
  f->stake_allow_zero_undelegated_amount = 200016004; // Allow zero-lamport undelegated amount for initialized stakes #24670
  f->credits_auto_rewind = 200448008; // Auto rewind stake's credits_observed if (accidental) vote recreation is detected #22546
  f->libsecp256k1_fail_on_bad_count2 = 200880004; // fail libsec256k1_verify if count appears wrong
  f->vote_state_update_root_fix = 202176000; // fix root in vote state updates #27361
  f->move_serialized_len_ptr_in_cpi = 202608000; // cpi ignore serialized_len_ptr #29592
  f->stake_split_uses_rent_sysvar = 203904008; // stake split instruction uses rent sysvar
  f->on_load_preserve_rent_epoch_for_rent_exempt_accounts = 204336000; // on bank load account, do not try to fix up rent_epoch #28541
  f->disable_rehash_for_rent_epoch = 204336000; // on accounts hash calculation, do not try to rehash accounts #28934
  f->fix_recent_blockhashes = 204768000; // stop adding hashes for skipped slots to recent blockhashes
  f->cap_bpf_program_instruction_accounts = 205200004; // enforce max number of accounts per bpf program instruction #26628
  f->update_rewards_from_cached_accounts = 206064004; // update rewards from cached accounts
  f->use_default_units_in_fee_calculation = 206496008; // use default units per instruction in fee calculation #26785
  f->disable_builtin_loader_ownership_chains = 207360004; // disable builtin loader ownership chains #29956
  f->check_slice_translation_size = 207792008; // check size when translating slices
  f->disable_fees_sysvar = 208656004; // disable fees sysvar
}
void fd_enable_v13(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->merge_nonce_error_into_system_error = 1; //
  f->optimize_epoch_boundary_updates = 1; //
  f->update_syscall_base_costs = 1; //
  f->disable_fee_calculator = 1; //
  f->include_account_index_in_rent_error = 1; //
  f->apply_cost_tracker_during_replay = 1; //
  f->fixed_memcpy_nonoverlapping_check = 1; //
  f->record_instruction_in_transaction_context_push = 1; //
  f->warp_timestamp_with_a_vengeance = 1; //
  f->check_init_vote_data = 1; //
  f->demote_program_write_locks = 1; //
  f->filter_votes_outside_slot_hashes = 1; //
  f->versioned_tx_message_enabled = 1; //
  f->nonce_must_be_advanceable = 1; //
  f->check_syscall_outputs_do_not_overlap = 1; //
  f->disable_bpf_deprecated_load_instructions = 1; //
  f->prevent_calling_precompiles_as_programs = 1; //
  f->add_compute_budget_program = 1; //
  f->drop_redundant_turbine_path = 1; //
  f->enable_durable_nonce = 1; //
  f->no_overflow_rent_distribution = 1; //
  f->pico_inflation = 1; //
  f->disable_bpf_unresolved_symbols_at_runtime = 1; //
  f->libsecp256k1_fail_on_bad_count2 = 1; //
  f->tx_wide_compute_cap = 1; //
  f->ed25519_program_enabled = 1; //
  f->secp256k1_recover_syscall_enabled = 1; //
  f->vote_authorize_with_seed = 1; //
  f->sol_log_data_syscall_enabled = 1; //
  f->do_support_realloc = 1; //
  f->limit_secp256k1_recovery_id = 1; //
  f->executables_incur_cpi_data_cost = 1; //
  f->curve25519_syscall_enabled = 1; //
  f->reject_non_rent_exempt_vote_withdraws = 1; //
  f->full_inflation_mainnet_certusoneenable = 1; //
  f->prevent_crediting_accounts_that_end_rent_paying = 1; //
  f->libsecp256k1_fail_on_bad_count = 1; //
  f->require_static_program_ids_in_transaction = 1; //
  f->dedupe_config_program_signers = 1; //
  f->add_set_compute_unit_price_ix = 1; //
  f->reject_empty_instruction_without_program = 1; //
  f->increase_tx_account_lock_limit = 1; //
  f->reject_vote_account_close_unless_zero_credit_epoch = 1; //
  f->vote_withdraw_authority_may_change_authorized_voter = 1; //
  f->vote_stake_checked_instructions = 1; //
  f->nonce_must_be_writable = 1; //
  f->rent_for_sysvars = 1; //
  f->require_rent_exempt_accounts = 1; //
  f->spl_token_v2_self_transfer_fix = 1; //
  f->system_transfer_zero_check = 1; //
  f->full_inflation_mainnet_certusone_vote = 1; //
  f->send_to_tpu_vote_port = 1; //
  f->cap_accounts_data_len = 1; //
  f->max_tx_account_locks = 1; //
  f->requestable_heap_size = 1; //
  f->add_get_processed_sibling_instruction_syscall = 1; //
  f->require_custodian_for_locked_stake_authorize = 1; //
  f->libsecp256k1_0_5_upgrade_enabled = 1; //
  f->quick_bail_on_panic = 1; //
  f->add_shred_type_to_shred_seed = 1; //
  f->full_inflation_devnet_and_testnet = 1; //
  f->return_data_syscall_enabled = 1; //
  f->secp256k1_program_enabled = 1; //
  f->spl_token_v2_multisig_fix = 1; //
  f->leave_nonce_on_success = 1; //
  f->reduce_required_deploy_balance = 1; //
  f->evict_invalid_stakes_cache_entries = 1; //
  f->verify_tx_signatures_len = 1; //
  f->spl_associated_token_account_v1_1_0 = 1; //
  f->spl_associated_token_account_v1_0_4 = 1; //
  f->allow_votes_to_directly_update_vote_state = 1; //
  f->spl_token_v3_3_0_release = 1; //
  f->spl_token_v3_4_0 = 1; //
  f->spl_token_v2_set_authority_fix = 1; //
  f->deprecate_rewards_sysvar = 1; //
  f->filter_stake_delegation_accounts = 1; //
  f->separate_nonce_from_blockhash = 1; //
  f->disable_deprecated_loader = 1; //
  f->warp_timestamp_again = 1; //
  f->instructions_sysvar_owned_by_sysvar = 1; //
  f->stakes_remove_delegation_if_inactive = 1; //
  f->preserve_rent_epoch_for_rent_exempt_accounts = 1; //
  f->remove_native_loader = 1; //
  f->blake3_syscall_enabled = 1; //
  f->nonce_must_be_authorized = 1; //
  f->syscall_saturated_math = 1; //
  f->default_units_per_instruction = 1; //
  f->disable_fees_sysvar = 1; //
  f->stake_merge_with_unmatched_credits_observed = 1; //
  f->check_physical_overlapping = 1; //
  f->cap_accounts_data_size_per_block = 1; //
  f->stake_program_advance_activating_credits_observed = 1; //
  f->stake_allow_zero_undelegated_amount = 1; //
  f->bank_transaction_count_fix = 1; //
  f->zk_token_sdk_enabled = 1; //
}
void fd_enable_v14(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->merge_nonce_error_into_system_error = 1; //
  f->incremental_snapshot_only_incremental_hash_calculation = 1; //
  f->optimize_epoch_boundary_updates = 1; //
  f->update_rewards_from_cached_accounts = 1; //
  f->update_syscall_base_costs = 1; //
  f->disable_fee_calculator = 1; //
  f->include_account_index_in_rent_error = 1; //
  f->fixed_memcpy_nonoverlapping_check = 1; //
  f->record_instruction_in_transaction_context_push = 1; //
  f->warp_timestamp_with_a_vengeance = 1; //
  f->check_init_vote_data = 1; //
  f->demote_program_write_locks = 1; //
  f->stake_redelegate_instruction = 1; //
  f->filter_votes_outside_slot_hashes = 1; //
  f->versioned_tx_message_enabled = 1; //
  f->reject_callx_r10 = 1; //
  f->nonce_must_be_advanceable = 1; //
  f->check_syscall_outputs_do_not_overlap = 1; //
  f->disable_bpf_deprecated_load_instructions = 1; //
  f->stake_deactivate_delinquent_instruction = 1; //
  f->prevent_calling_precompiles_as_programs = 1; //
  f->add_compute_budget_program = 1; //
  f->drop_redundant_turbine_path = 1; //
  f->enable_durable_nonce = 1; //
  f->no_overflow_rent_distribution = 1; //
  f->pico_inflation = 1; //
  f->disable_builtin_loader_ownership_chains = 1; //
  f->disable_bpf_unresolved_symbols_at_runtime = 1; //
  f->libsecp256k1_fail_on_bad_count2 = 1; //
  f->tx_wide_compute_cap = 1; //
  f->fix_recent_blockhashes = 1; //
  f->ed25519_program_enabled = 1; //
  f->secp256k1_recover_syscall_enabled = 1; //
  f->vote_authorize_with_seed = 1; //
  f->sol_log_data_syscall_enabled = 1; //
  f->move_serialized_len_ptr_in_cpi = 1; //
  f->do_support_realloc = 1; //
  f->disable_deploy_of_alloc_free_syscall = 1; //
  f->limit_secp256k1_recovery_id = 1; //
  f->executables_incur_cpi_data_cost = 1; //
  f->curve25519_syscall_enabled = 1; //
  f->reject_non_rent_exempt_vote_withdraws = 1; //
  f->enable_early_verification_of_account_modifications = 1; //
  f->full_inflation_mainnet_certusoneenable = 1; //
  f->prevent_crediting_accounts_that_end_rent_paying = 1; //
  f->error_on_syscall_bpf_function_hash_collisions = 1; //
  f->drop_merkle_shreds = 1; //
  f->compact_vote_state_updates = 1; //
  f->libsecp256k1_fail_on_bad_count = 1; //
  f->require_static_program_ids_in_transaction = 1; //
  f->dedupe_config_program_signers = 1; //
  f->use_default_units_in_fee_calculation = 1; //
  f->enable_bpf_loader_extend_program_ix = 1; //
  f->add_set_compute_unit_price_ix = 1; //
  f->cap_bpf_program_instruction_accounts = 1; //
  f->reject_empty_instruction_without_program = 1; //
  f->increase_tx_account_lock_limit = 1; //
  f->stake_raise_minimum_delegation_to_1_sol = 1; //
  f->reject_vote_account_close_unless_zero_credit_epoch = 1; //
  f->vote_withdraw_authority_may_change_authorized_voter = 1; //
  f->vote_stake_checked_instructions = 1; //
  f->nonce_must_be_writable = 1; //
  f->clean_up_delegation_errors = 1; //
  f->rent_for_sysvars = 1; //
  f->require_rent_exempt_accounts = 1; //
  f->spl_token_v2_self_transfer_fix = 1; //
  f->system_transfer_zero_check = 1; //
  f->credits_auto_rewind = 1; //
  f->full_inflation_mainnet_certusone_vote = 1; //
  f->send_to_tpu_vote_port = 1; //
  f->cap_accounts_data_len = 1; //
  f->max_tx_account_locks = 1; //
  f->requestable_heap_size = 1; //
  f->add_get_processed_sibling_instruction_syscall = 1; //
  f->on_load_preserve_rent_epoch_for_rent_exempt_accounts = 1; //
  f->vote_state_update_credit_per_dequeue = 1; //
  f->enable_turbine_fanout_experiments = 1; //
  f->require_custodian_for_locked_stake_authorize = 1; //
  f->libsecp256k1_0_5_upgrade_enabled = 1; //
  f->quick_bail_on_panic = 1; //
  f->add_shred_type_to_shred_seed = 1; //
  f->full_inflation_devnet_and_testnet = 1; //
  f->disable_rehash_for_rent_epoch = 1; //
  f->return_data_syscall_enabled = 1; //
  f->secp256k1_program_enabled = 1; //
  f->spl_token_v2_multisig_fix = 1; //
  f->leave_nonce_on_success = 1; //
  f->reduce_required_deploy_balance = 1; //
  f->stake_minimum_delegation_for_rewards = 1; //
  f->evict_invalid_stakes_cache_entries = 1; //
  f->verify_tx_signatures_len = 1; //
  f->spl_associated_token_account_v1_1_0 = 1; //
  f->spl_associated_token_account_v1_0_4 = 1; //
  f->allow_votes_to_directly_update_vote_state = 1; //
  f->stake_split_uses_rent_sysvar = 1; //
  f->spl_token_v3_3_0_release = 1; //
  f->spl_token_v3_4_0 = 1; //
  f->spl_token_v2_set_authority_fix = 1; //
  f->vote_state_update_root_fix = 1; //
  f->deprecate_rewards_sysvar = 1; //
  f->loosen_cpi_size_restriction = 1; //
  f->filter_stake_delegation_accounts = 1; //
  f->separate_nonce_from_blockhash = 1; //
  f->check_slice_translation_size = 1; //
  f->disable_deprecated_loader = 1; //
  f->warp_timestamp_again = 1; //
  f->disable_turbine_fanout_experiments = 1; //
  f->instructions_sysvar_owned_by_sysvar = 1; //
  f->stakes_remove_delegation_if_inactive = 1; //
  f->preserve_rent_epoch_for_rent_exempt_accounts = 1; //
  f->enable_request_heap_frame_ix = 1; //
  f->remove_native_loader = 1; //
  f->blake3_syscall_enabled = 1; //
  f->nonce_must_be_authorized = 1; //
  f->keep_merkle_shreds = 1; //
  f->syscall_saturated_math = 1; //
  f->default_units_per_instruction = 1; //
  f->disable_fees_sysvar = 1; //
  f->stake_merge_with_unmatched_credits_observed = 1; //
  f->commission_updates_only_allowed_in_first_half_of_epoch = 1; //
  f->check_physical_overlapping = 1; //
  f->cap_accounts_data_size_per_block = 1; //
  f->stake_program_advance_activating_credits_observed = 1; //
  f->add_get_minimum_delegation_instruction_to_stake_program = 1; //
  f->stake_allow_zero_undelegated_amount = 1; //
  f->bank_transaction_count_fix = 1; //
  f->zk_token_sdk_enabled = 1; //
}
void fd_enable_v16(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->stop_truncating_strings_in_syscalls = 1; //
  f->merge_nonce_error_into_system_error = 1; //
  f->incremental_snapshot_only_incremental_hash_calculation = 1; //
  f->optimize_epoch_boundary_updates = 1; //
  f->update_rewards_from_cached_accounts = 1; //
  f->update_syscall_base_costs = 1; //
  f->remove_bpf_loader_incorrect_program_id = 1; //
  f->disable_fee_calculator = 1; //
  f->include_account_index_in_rent_error = 1; //
  f->apply_cost_tracker_during_replay = 1; //
  f->fixed_memcpy_nonoverlapping_check = 1; //
  f->record_instruction_in_transaction_context_push = 1; //
  f->warp_timestamp_with_a_vengeance = 1; //
  f->check_init_vote_data = 1; //
  f->demote_program_write_locks = 1; //
  f->stake_redelegate_instruction = 1; //
  f->filter_votes_outside_slot_hashes = 1; //
  f->versioned_tx_message_enabled = 1; //
  f->reject_callx_r10 = 1; //
  f->nonce_must_be_advanceable = 1; //
  f->update_hashes_per_tick = 1; //
  f->check_syscall_outputs_do_not_overlap = 1; //
  f->disable_bpf_deprecated_load_instructions = 1; //
  f->stake_deactivate_delinquent_instruction = 1; //
  f->prevent_calling_precompiles_as_programs = 1; //
  f->add_compute_budget_program = 1; //
  f->drop_redundant_turbine_path = 1; //
  f->enable_durable_nonce = 1; //
  f->no_overflow_rent_distribution = 1; //
  f->pico_inflation = 1; //
  f->disable_builtin_loader_ownership_chains = 1; //
  f->disable_bpf_unresolved_symbols_at_runtime = 1; //
  f->libsecp256k1_fail_on_bad_count2 = 1; //
  f->tx_wide_compute_cap = 1; //
  f->epoch_accounts_hash = 1; //
  f->checked_arithmetic_in_fee_validation = 1; //
  f->set_exempt_rent_epoch_max = 1; //
  f->enable_bpf_loader_set_authority_checked_ix = 1; //
  f->simplify_writable_program_account_check = 1; //
  f->fix_recent_blockhashes = 1; //
  f->ed25519_program_enabled = 1; //
  f->secp256k1_recover_syscall_enabled = 1; //
  f->vote_authorize_with_seed = 1; //
  f->sol_log_data_syscall_enabled = 1; //
  f->move_serialized_len_ptr_in_cpi = 1; //
  f->do_support_realloc = 1; //
  f->disable_deploy_of_alloc_free_syscall = 1; //
  f->vote_state_add_vote_latency = 1; //
  f->limit_secp256k1_recovery_id = 1; //
  f->executables_incur_cpi_data_cost = 1; //
  f->curve25519_syscall_enabled = 1; //
  f->reject_non_rent_exempt_vote_withdraws = 1; //
  f->enable_early_verification_of_account_modifications = 1; //
  f->full_inflation_mainnet_certusoneenable = 1; //
  f->prevent_crediting_accounts_that_end_rent_paying = 1; //
  f->error_on_syscall_bpf_function_hash_collisions = 1; //
  f->drop_merkle_shreds = 1; //
  f->compact_vote_state_updates = 1; //
  f->libsecp256k1_fail_on_bad_count = 1; //
  f->require_static_program_ids_in_transaction = 1; //
  f->dedupe_config_program_signers = 1; //
  f->native_programs_consume_cu = 1; //
  f->use_default_units_in_fee_calculation = 1; //
  f->enable_bpf_loader_extend_program_ix = 1; //
  f->add_set_compute_unit_price_ix = 1; //
  f->bpf_account_data_direct_mapping = 1; //
  f->cap_accounts_data_allocations_per_transaction = 1; //
  f->cap_bpf_program_instruction_accounts = 1; //
  f->reject_empty_instruction_without_program = 1; //
  f->increase_tx_account_lock_limit = 1; //
  f->stake_raise_minimum_delegation_to_1_sol = 1; //
  f->enable_alt_bn128_syscall = 1; //
  f->remove_congestion_multiplier_from_fee_calculation = 1; //
  f->reject_vote_account_close_unless_zero_credit_epoch = 1; //
  f->vote_withdraw_authority_may_change_authorized_voter = 1; //
  f->disable_cpi_setting_executable_and_rent_epoch = 1; //
  f->vote_stake_checked_instructions = 1; //
  f->nonce_must_be_writable = 1; //
  f->clean_up_delegation_errors = 1; //
  f->rent_for_sysvars = 1; //
  f->require_rent_exempt_accounts = 1; //
  f->spl_token_v2_self_transfer_fix = 1; //
  f->system_transfer_zero_check = 1; //
  f->credits_auto_rewind = 1; //
  f->full_inflation_mainnet_certusone_vote = 1; //
  f->send_to_tpu_vote_port = 1; //
  f->cap_accounts_data_len = 1; //
  f->max_tx_account_locks = 1; //
  f->requestable_heap_size = 1; //
  f->switch_to_new_elf_parser = 1; //
  f->round_up_heap_size = 1; //
  f->add_get_processed_sibling_instruction_syscall = 1; //
  f->skip_rent_rewrites = 1; //
  f->on_load_preserve_rent_epoch_for_rent_exempt_accounts = 1; //
  f->vote_state_update_credit_per_dequeue = 1; //
  f->enable_turbine_fanout_experiments = 1; //
  f->require_custodian_for_locked_stake_authorize = 1; //
  f->cap_transaction_accounts_data_size = 1; //
  f->libsecp256k1_0_5_upgrade_enabled = 1; //
  f->quick_bail_on_panic = 1; //
  f->add_shred_type_to_shred_seed = 1; //
  f->full_inflation_devnet_and_testnet = 1; //
  f->disable_rehash_for_rent_epoch = 1; //
  f->return_data_syscall_enabled = 1; //
  f->secp256k1_program_enabled = 1; //
  f->spl_token_v2_multisig_fix = 1; //
  f->leave_nonce_on_success = 1; //
  f->include_loaded_accounts_data_size_in_fee_calculation = 1; //
  f->reduce_required_deploy_balance = 1; //
  f->enable_big_mod_exp_syscall = 1; //
  f->remove_deprecated_request_unit_ix = 1; //
  f->stake_minimum_delegation_for_rewards = 1; //
  f->evict_invalid_stakes_cache_entries = 1; //
  f->verify_tx_signatures_len = 1; //
  f->stop_sibling_instruction_search_at_parent = 1; //
  f->prevent_rent_paying_rent_recipients = 1; //
  f->spl_associated_token_account_v1_1_0 = 1; //
  f->spl_associated_token_account_v1_0_4 = 1; //
  f->allow_votes_to_directly_update_vote_state = 1; //
  f->relax_authority_signer_check_for_lookup_table_creation = 1; //
  f->stake_split_uses_rent_sysvar = 1; //
  f->spl_token_v3_3_0_release = 1; //
  f->spl_token_v3_4_0 = 1; //
  f->spl_token_v2_set_authority_fix = 1; //
  f->add_set_tx_loaded_accounts_data_size_instruction = 1; //
  f->vote_state_update_root_fix = 1; //
  f->deprecate_rewards_sysvar = 1; //
  f->loosen_cpi_size_restriction = 1; //
  f->filter_stake_delegation_accounts = 1; //
  f->separate_nonce_from_blockhash = 1; //
  f->check_slice_translation_size = 1; //
  f->delay_visibility_of_program_deployment = 1; //
  f->limit_max_instruction_trace_length = 1; //
  f->disable_deprecated_loader = 1; //
  f->warp_timestamp_again = 1; //
  f->disable_turbine_fanout_experiments = 1; //
  f->instructions_sysvar_owned_by_sysvar = 1; //
  f->stakes_remove_delegation_if_inactive = 1; //
  f->preserve_rent_epoch_for_rent_exempt_accounts = 1; //
  f->enable_request_heap_frame_ix = 1; //
  f->remove_native_loader = 1; //
  f->blake3_syscall_enabled = 1; //
  f->nonce_must_be_authorized = 1; //
  f->keep_merkle_shreds = 1; //
  f->syscall_saturated_math = 1; //
  f->default_units_per_instruction = 1; //
  f->enable_program_redeployment_cooldown = 1; //
  f->disable_fees_sysvar = 1; //
  f->stake_merge_with_unmatched_credits_observed = 1; //
  f->commission_updates_only_allowed_in_first_half_of_epoch = 1; //
  f->check_physical_overlapping = 1; //
  f->cap_accounts_data_size_per_block = 1; //
  f->stake_program_advance_activating_credits_observed = 1; //
  f->add_get_minimum_delegation_instruction_to_stake_program = 1; //
  f->stake_allow_zero_undelegated_amount = 1; //
  f->account_hash_ignore_slot = 1; //
  f->bank_transaction_count_fix = 1; //
  f->zk_token_sdk_enabled = 1; //
}
void fd_enable_v17(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->stop_truncating_strings_in_syscalls = 1; //
  f->merge_nonce_error_into_system_error = 1; //
  f->incremental_snapshot_only_incremental_hash_calculation = 1; //
  f->optimize_epoch_boundary_updates = 1; //
  f->update_rewards_from_cached_accounts = 1; //
  f->update_syscall_base_costs = 1; //
  f->remove_bpf_loader_incorrect_program_id = 1; //
  f->disable_fee_calculator = 1; //
  f->include_account_index_in_rent_error = 1; //
  f->apply_cost_tracker_during_replay = 1; //
  f->fixed_memcpy_nonoverlapping_check = 1; //
  f->record_instruction_in_transaction_context_push = 1; //
  f->warp_timestamp_with_a_vengeance = 1; //
  f->check_init_vote_data = 1; //
  f->demote_program_write_locks = 1; //
  f->stake_redelegate_instruction = 1; //
  f->filter_votes_outside_slot_hashes = 1; //
  f->versioned_tx_message_enabled = 1; //
  f->reject_callx_r10 = 1; //
  f->nonce_must_be_advanceable = 1; //
  f->update_hashes_per_tick = 1; //
  f->check_syscall_outputs_do_not_overlap = 1; //
  f->disable_bpf_deprecated_load_instructions = 1; //
  f->stake_deactivate_delinquent_instruction = 1; //
  f->prevent_calling_precompiles_as_programs = 1; //
  f->add_compute_budget_program = 1; //
  f->drop_redundant_turbine_path = 1; //
  f->enable_durable_nonce = 1; //
  f->no_overflow_rent_distribution = 1; //
  f->pico_inflation = 1; //
  f->disable_builtin_loader_ownership_chains = 1; //
  f->disable_bpf_unresolved_symbols_at_runtime = 1; //
  f->libsecp256k1_fail_on_bad_count2 = 1; //
  f->tx_wide_compute_cap = 1; //
  f->epoch_accounts_hash = 1; //
  f->checked_arithmetic_in_fee_validation = 1; //
  f->set_exempt_rent_epoch_max = 1; //
  f->enable_bpf_loader_set_authority_checked_ix = 1; //
  f->simplify_writable_program_account_check = 1; //
  f->fix_recent_blockhashes = 1; //
  f->ed25519_program_enabled = 1; //
  f->secp256k1_recover_syscall_enabled = 1; //
  f->vote_authorize_with_seed = 1; //
  f->sol_log_data_syscall_enabled = 1; //
  f->move_serialized_len_ptr_in_cpi = 1; //
  f->do_support_realloc = 1; //
  f->disable_deploy_of_alloc_free_syscall = 1; //
  f->vote_state_add_vote_latency = 1; //
  f->limit_secp256k1_recovery_id = 1; //
  f->executables_incur_cpi_data_cost = 1; //
  f->curve25519_syscall_enabled = 1; //
  f->reject_non_rent_exempt_vote_withdraws = 1; //
  f->enable_early_verification_of_account_modifications = 1; //
  f->full_inflation_mainnet_certusoneenable = 1; //
  f->prevent_crediting_accounts_that_end_rent_paying = 1; //
  f->error_on_syscall_bpf_function_hash_collisions = 1; //
  f->drop_merkle_shreds = 1; //
  f->compact_vote_state_updates = 1; //
  f->libsecp256k1_fail_on_bad_count = 1; //
  f->require_static_program_ids_in_transaction = 1; //
  f->dedupe_config_program_signers = 1; //
  f->native_programs_consume_cu = 1; //
  f->use_default_units_in_fee_calculation = 1; //
  f->enable_bpf_loader_extend_program_ix = 1; //
  f->add_set_compute_unit_price_ix = 1; //
  f->bpf_account_data_direct_mapping = 1; //
  f->cap_accounts_data_allocations_per_transaction = 1; //
  f->cap_bpf_program_instruction_accounts = 1; //
  f->reject_empty_instruction_without_program = 1; //
  f->increase_tx_account_lock_limit = 1; //
  f->stake_raise_minimum_delegation_to_1_sol = 1; //
  f->enable_alt_bn128_syscall = 1; //
  f->remove_congestion_multiplier_from_fee_calculation = 1; //
  f->reject_vote_account_close_unless_zero_credit_epoch = 1; //
  f->vote_withdraw_authority_may_change_authorized_voter = 1; //
  f->disable_cpi_setting_executable_and_rent_epoch = 1; //
  f->vote_stake_checked_instructions = 1; //
  f->nonce_must_be_writable = 1; //
  f->clean_up_delegation_errors = 1; //
  f->rent_for_sysvars = 1; //
  f->require_rent_exempt_accounts = 1; //
  f->spl_token_v2_self_transfer_fix = 1; //
  f->system_transfer_zero_check = 1; //
  f->credits_auto_rewind = 1; //
  f->full_inflation_mainnet_certusone_vote = 1; //
  f->send_to_tpu_vote_port = 1; //
  f->cap_accounts_data_len = 1; //
  f->max_tx_account_locks = 1; //
  f->requestable_heap_size = 1; //
  f->switch_to_new_elf_parser = 1; //
  f->round_up_heap_size = 1; //
  f->add_get_processed_sibling_instruction_syscall = 1; //
  f->skip_rent_rewrites = 1; //
  f->on_load_preserve_rent_epoch_for_rent_exempt_accounts = 1; //
  f->vote_state_update_credit_per_dequeue = 1; //
  f->enable_turbine_fanout_experiments = 1; //
  f->require_custodian_for_locked_stake_authorize = 1; //
  f->cap_transaction_accounts_data_size = 1; //
  f->libsecp256k1_0_5_upgrade_enabled = 1; //
  f->quick_bail_on_panic = 1; //
  f->add_shred_type_to_shred_seed = 1; //
  f->full_inflation_devnet_and_testnet = 1; //
  f->disable_rehash_for_rent_epoch = 1; //
  f->return_data_syscall_enabled = 1; //
  f->secp256k1_program_enabled = 1; //
  f->spl_token_v2_multisig_fix = 1; //
  f->leave_nonce_on_success = 1; //
  f->include_loaded_accounts_data_size_in_fee_calculation = 1; //
  f->reduce_required_deploy_balance = 1; //
  f->enable_big_mod_exp_syscall = 1; //
  f->remove_deprecated_request_unit_ix = 1; //
  f->stake_minimum_delegation_for_rewards = 1; //
  f->evict_invalid_stakes_cache_entries = 1; //
  f->verify_tx_signatures_len = 1; //
  f->stop_sibling_instruction_search_at_parent = 1; //
  f->prevent_rent_paying_rent_recipients = 1; //
  f->spl_associated_token_account_v1_1_0 = 1; //
  f->spl_associated_token_account_v1_0_4 = 1; //
  f->allow_votes_to_directly_update_vote_state = 1; //
  f->relax_authority_signer_check_for_lookup_table_creation = 1; //
  f->stake_split_uses_rent_sysvar = 1; //
  f->spl_token_v3_3_0_release = 1; //
  f->spl_token_v3_4_0 = 1; //
  f->spl_token_v2_set_authority_fix = 1; //
  f->add_set_tx_loaded_accounts_data_size_instruction = 1; //
  f->vote_state_update_root_fix = 1; //
  f->deprecate_rewards_sysvar = 1; //
  f->loosen_cpi_size_restriction = 1; //
  f->filter_stake_delegation_accounts = 1; //
  f->separate_nonce_from_blockhash = 1; //
  f->check_slice_translation_size = 1; //
  f->delay_visibility_of_program_deployment = 1; //
  f->limit_max_instruction_trace_length = 1; //
  f->disable_deprecated_loader = 1; //
  f->warp_timestamp_again = 1; //
  f->disable_turbine_fanout_experiments = 1; //
  f->instructions_sysvar_owned_by_sysvar = 1; //
  f->enable_partitioned_epoch_reward = 1; //
  f->stakes_remove_delegation_if_inactive = 1; //
  f->preserve_rent_epoch_for_rent_exempt_accounts = 1; //
  f->last_restart_slot_sysvar = 1; //
  f->enable_request_heap_frame_ix = 1; //
  f->remove_native_loader = 1; //
  f->blake3_syscall_enabled = 1; //
  f->nonce_must_be_authorized = 1; //
  f->keep_merkle_shreds = 1; //
  f->syscall_saturated_math = 1; //
  f->default_units_per_instruction = 1; //
  f->enable_program_redeployment_cooldown = 1; //
  f->disable_fees_sysvar = 1; //
  f->stake_merge_with_unmatched_credits_observed = 1; //
  f->commission_updates_only_allowed_in_first_half_of_epoch = 1; //
  f->check_physical_overlapping = 1; //
  f->cap_accounts_data_size_per_block = 1; //
  f->stake_program_advance_activating_credits_observed = 1; //
  f->add_get_minimum_delegation_instruction_to_stake_program = 1; //
  f->stake_allow_zero_undelegated_amount = 1; //
  f->account_hash_ignore_slot = 1; //
  f->bank_transaction_count_fix = 1; //
  f->zk_token_sdk_enabled = 1; //
}
void fd_enable_everything(struct fd_features *f) {
  fd_memset(f, 0, sizeof(*f));
  f->account_hash_ignore_slot = 1; // SVn36yVApPLYsa8koK3qUcy14zXDnqkNYWyUh1f4oK1
  f->add_compute_budget_program = 1; // 4d5AKtxoh93Dwm1vHXUU3iRATuMndx1c431KgT2td52r
  f->add_get_minimum_delegation_instruction_to_stake_program = 1; // St8k9dVXP97xT6faW24YmRSYConLbhsMJA4TJTBLmMT
  f->add_get_processed_sibling_instruction_syscall = 1; // CFK1hRCNy8JJuAAY8Pb2GjLFNdCThS2qwZNe3izzBMgn
  f->add_set_compute_unit_price_ix = 1; // 98std1NSHqXi9WYvFShfVepRdCoq1qvsp8fsR2XZtG8g
  f->add_set_tx_loaded_accounts_data_size_instruction = 1; // G6vbf1UBok8MWb8m25ex86aoQHeKTzDKzuZADHkShqm6
  f->add_shred_type_to_shred_seed = 1; // Ds87KVeqhbv7Jw8W6avsS1mqz3Mw5J3pRTpPoDQ2QdiJ
  f->allow_votes_to_directly_update_vote_state = 1; // Ff8b1fBeB86q8cjq47ZhsQLgv5EkHu3G1C99zjUfAzrq
  f->apply_cost_tracker_during_replay = 1; // 2ry7ygxiYURULZCrypHhveanvP5tzZ4toRwVp89oCNSj
  f->bank_transaction_count_fix = 1; // Vo5siZ442SaZBKPXNocthiXysNviW4UYPwRFggmbgAp
  f->blake3_syscall_enabled = 1; // HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3
  f->bpf_account_data_direct_mapping = 1; // 9gwzizfABsKUereT6phZZxbTzuAnovkgwpVVpdcSxv9h
  f->cap_accounts_data_allocations_per_transaction = 1; // 9gxu85LYRAcZL38We8MYJ4A9AwgBBPtVBAqebMcT1241
  f->cap_accounts_data_len = 1; // capRxUrBjNkkCpjrJxPGfPaWijB7q3JoDfsWXAnt46r
  f->cap_accounts_data_size_per_block = 1; // qywiJyZmqTKspFg2LeuUHqcA5nNvBgobqb9UprywS9N
  f->cap_bpf_program_instruction_accounts = 1; // 9k5ijzTbYPtjzu8wj2ErH9v45xecHzQ1x4PMYMMxFgdM
  f->cap_transaction_accounts_data_size = 1; // DdLwVYuvDz26JohmgSbA7mjpJFgX5zP2dkp8qsF2C33V
  f->check_init_vote_data = 1; // 3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F
  f->check_physical_overlapping = 1; // nWBqjr3gpETbiaVj3CBJ3HFC5TMdnJDGt21hnvSTvVZ
  f->check_slice_translation_size = 1; // GmC19j9qLn2RFk5NduX6QXaDhVpGncVVBzyM8e9WMz2F
  f->check_syscall_outputs_do_not_overlap = 1; // 3uRVPBpyEJRo1emLCrq38eLRFGcu6uKSpUXqGvU8T7SZ
  f->checked_arithmetic_in_fee_validation = 1; // 5Pecy6ie6XGm22pc9d4P9W5c31BugcFBuy6hsP2zkETv
  f->clean_up_delegation_errors = 1; // Bj2jmUsM2iRhfdLLDSTkhM5UQRQvQHm57HSmPibPtEyu
  f->commission_updates_only_allowed_in_first_half_of_epoch = 1; // noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp
  f->compact_vote_state_updates = 1; // 86HpNqzutEZwLcPxS6EHDcMNYWk6ikhteg9un7Y2PBKE
  f->credits_auto_rewind = 1; // BUS12ciZ5gCoFafUHWW8qaFMMtwFQGVxjsDheWLdqBE2
  f->curve25519_syscall_enabled = 1; // 7rcw5UtqgDTBBv2EcynNfYckgdAaH1MAsCjKgXMkN7Ri
  f->dedupe_config_program_signers = 1; // 8kEuAshXLsgkUEdcFVLqrjCGGHVWFW99ZZpxvAzzMtBp
  f->default_units_per_instruction = 1; // J2QdYx8crLbTVK8nur1jeLsmc3krDbfjoxoea2V1Uy5Q
  f->delay_visibility_of_program_deployment = 1; // GmuBvtFb2aHfSfMXpuFeWZGHyDeCLPS79s48fmCWCfM5
  f->demote_program_write_locks = 1; // 3E3jV7v9VcdJL8iYZUMax9DiDno8j7EWUVbhm9RtShj2
  f->deprecate_rewards_sysvar = 1; // GaBtBJvmS4Arjj5W1NmFcyvPjsHN38UGYDq2MDwbs9Qu
  f->disable_bpf_deprecated_load_instructions = 1; // 3XgNukcZWf9o3HdA3fpJbm94XFc4qpvTXc8h1wxYwiPi
  f->disable_bpf_unresolved_symbols_at_runtime = 1; // 4yuaYAj2jGMGTh1sSmi4G2eFscsDq8qjugJXZoBN6YEa
  f->disable_builtin_loader_ownership_chains = 1; // 4UDcAfQ6EcA6bdcadkeHpkarkhZGJ7Bpq7wTAiRMjkoi
  f->disable_cpi_setting_executable_and_rent_epoch = 1; // B9cdB55u4jQsDNsdTK525yE9dmSc5Ga7YBaBrDFvEhM9
  f->disable_deploy_of_alloc_free_syscall = 1; // 79HWsX9rpnnJBPcdNURVqygpMAfxdrAirzAGAVmf92im
  f->disable_deprecated_loader = 1; // GTUMCZ8LTNxVfxdrw7ZsDFTxXb7TutYkzJnFwinpE6dg
  f->disable_fee_calculator = 1; // 2jXx2yDmGysmBKfKYNgLj2DQyAQv6mMk2BPh4eSbyB4H
  f->disable_fees_sysvar = 1; // JAN1trEUEtZjgXYzNBYHU9DYd7GnThhXfFP7SzPXkPsG
  f->disable_rehash_for_rent_epoch = 1; // DTVTkmw3JSofd8CJVJte8PXEbxNQ2yZijvVr3pe2APPj
  f->disable_turbine_fanout_experiments = 1; // Gz1aLrbeQ4Q6PTSafCZcGWZXz91yVRi7ASFzFEr1U4sa
  f->do_support_realloc = 1; // 75m6ysz33AfLA5DDEzWM1obBrnPQRSsdVQ2nRmc8Vuu1
  f->drop_merkle_shreds = 1; // 84zy5N23Q9vTZuLc9h1HWUtyM9yCFV2SCmyP9W9C3yHZ
  f->drop_redundant_turbine_path = 1; // 4Di3y24QFLt5QEUPZtbnjyfQKfm6ZMTfa6Dw1psfoMKU
  f->ed25519_program_enabled = 1; // 6ppMXNYLhVd7GcsZ5uV11wQEW7spppiMVfqQv5SXhDpX
  f->enable_alt_bn128_syscall = 1; // A16q37opZdQMCbe5qJ6xpBB9usykfv8jZaMkxvZQi4GJ
  f->enable_big_mod_exp_syscall = 1; // EBq48m8irRKuE7ZnMTLvLg2UuGSqhe8s8oMqnmja1fJw
  f->enable_bpf_loader_extend_program_ix = 1; // 8Zs9W7D9MpSEtUWSQdGniZk2cNmV22y6FLJwCx53asme
  f->enable_bpf_loader_set_authority_checked_ix = 1; // 5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL
  f->enable_durable_nonce = 1; // 4EJQtF2pkRyawwcTVfQutzq4Sa5hRhibF6QAK1QXhtEX
  f->enable_early_verification_of_account_modifications = 1; // 7Vced912WrRnfjaiKRiNBcbuFw7RrnLv3E3z95Y4GTNc
  f->enable_partitioned_epoch_reward = 1; // HCnE3xQoZtDz9dSVm3jKwJXioTb6zMRbgwCmGg3PHHk8
  f->enable_program_redeployment_cooldown = 1; // J4HFT8usBxpcF63y46t1upYobJgChmKyZPm5uTBRg25Z
  f->enable_request_heap_frame_ix = 1; // Hr1nUA9b7NJ6eChS26o7Vi8gYYDDwWD3YeBfzJkTbU86
  f->enable_turbine_fanout_experiments = 1; // D31EFnLgdiysi84Woo3of4JMu7VmasUS3Z7j9HYXCeLY
  f->epoch_accounts_hash = 1; // 5GpmAKxaGsWWbPp4bNXFLJxZVvG92ctxf7jQnzTQjF3n
  f->error_on_syscall_bpf_function_hash_collisions = 1; // 8199Q2gMD2kwgfopK5qqVWuDbegLgpuFUFHCcUJQDN8b
  f->evict_invalid_stakes_cache_entries = 1; // EMX9Q7TVFAmQ9V1CggAkhMzhXSg8ECp7fHrWQX2G1chf
  f->executables_incur_cpi_data_cost = 1; // 7GUcYgq4tVtaqNCKT3dho9r4665Qp5TxCZ27Qgjx3829
  f->filter_stake_delegation_accounts = 1; // GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi
  f->filter_votes_outside_slot_hashes = 1; // 3gtZPqvPpsbXZVCx6hceMfWxtsmrjMzmg8C7PLKSxS2d
  f->fix_recent_blockhashes = 1; // 6iyggb5MTcsvdcugX7bEKbHV8c6jdLbpHwkncrgLMhfo
  f->fixed_memcpy_nonoverlapping_check = 1; // 36PRUK2Dz6HWYdG9SpjeAsF5F3KxnFCakA2BZMbtMhSb
  f->full_inflation_devnet_and_testnet = 1; // DT4n6ABDqs6w4bnfwrXT9rsprcPf6cdDga1egctaPkLC
  f->full_inflation_mainnet_certusone_vote = 1; // BzBBveUDymEYoYzcMWNQCx3cd4jQs7puaVFHLtsbB6fm
  f->full_inflation_mainnet_certusoneenable = 1; // 7XRJcS5Ud5vxGB54JbK9N2vBZVwnwdBNeJW1ibRgD9gx
  f->include_account_index_in_rent_error = 1; // 2R72wpcQ7qV7aTJWUumdn8u5wmmTyXbK7qzEy7YSAgyY
  f->include_loaded_accounts_data_size_in_fee_calculation = 1; // EaQpmC6GtRssaZ3PCUM5YksGqUdMLeZ46BQXYtHYakDS
  f->increase_tx_account_lock_limit = 1; // 9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK
  f->incremental_snapshot_only_incremental_hash_calculation = 1; // 25vqsfjk7Nv1prsQJmA4Xu1bN61s8LXCBGUPp8Rfy1UF
  f->instructions_sysvar_owned_by_sysvar = 1; // H3kBSaKdeiUsyHmeHqjJYNc27jesXZ6zWj3zWkowQbkV
  f->keep_merkle_shreds = 1; // HyNQzc7TMNmRhpVHXqDGjpsHzeQie82mDQXSF9hj7nAH
  f->last_restart_slot_sysvar = 1; // HooKD5NC9QNxk25QuzCssB8ecrEzGt6eXEPBUxWp1LaR
  f->leave_nonce_on_success = 1; // E8MkiWZNNPGU6n55jkGzyj8ghUmjCHRmDFdYYFYHxWhQ
  f->libsecp256k1_0_5_upgrade_enabled = 1; // DhsYfRjxfnh2g7HKJYSzT79r74Afa1wbHkAgHndrA1oy
  f->libsecp256k1_fail_on_bad_count = 1; // 8aXvSuopd1PUj7UhehfXJRg6619RHp8ZvwTyyJHdUYsj
  f->libsecp256k1_fail_on_bad_count2 = 1; // 54KAoNiUERNoWWUhTWWwXgym94gzoXFVnHyQwPA18V9A
  f->limit_max_instruction_trace_length = 1; // GQALDaC48fEhZGWRj9iL5Q889emJKcj3aCvHF7VCbbF4
  f->limit_secp256k1_recovery_id = 1; // 7g9EUwj4j7CS21Yx1wvgWLjSZeh5aPq8x9kpoPwXM8n8
  f->loosen_cpi_size_restriction = 1; // GDH5TVdbTPUpRnXaRyQqiKUa7uZAbZ28Q2N9bhbKoMLm
  f->max_tx_account_locks = 1; // CBkDroRDqm8HwHe6ak9cguPjUomrASEkfmxEaZ5CNNxz
  f->merge_nonce_error_into_system_error = 1; // 21AWDosvp3pBamFW91KB35pNoaoZVTM7ess8nr2nt53B
  f->move_serialized_len_ptr_in_cpi = 1; // 74CoWuBmt3rUVUrCb2JiSTvh6nXyBWUsK4SaMj3CtE3T
  f->native_programs_consume_cu = 1; // 8pgXCMNXC8qyEFypuwpXyRxLXZdpM4Qo72gJ6k87A6wL
  f->no_overflow_rent_distribution = 1; // 4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz
  f->nonce_must_be_advanceable = 1; // 3u3Er5Vc2jVcwz4xr2GJeSAXT3fAj6ADHZ4BJMZiScFd
  f->nonce_must_be_authorized = 1; // HxrEu1gXuH7iD3Puua1ohd5n4iUKJyFNtNxk9DVJkvgr
  f->nonce_must_be_writable = 1; // BiCU7M5w8ZCMykVSyhZ7Q3m2SWoR2qrEQ86ERcDX77ME
  f->on_load_preserve_rent_epoch_for_rent_exempt_accounts = 1; // CpkdQmspsaZZ8FVAouQTtTWZkc8eeQ7V3uj7dWz543rZ
  f->optimize_epoch_boundary_updates = 1; // 265hPS8k8xJ37ot82KEgjRunsUp5w4n4Q4VwwiN9i9ps
  f->pico_inflation = 1; // 4RWNif6C2WCNiKVW7otP4G7dkmkHGyKQWRpuZ1pxKU5m
  f->preserve_rent_epoch_for_rent_exempt_accounts = 1; // HH3MUYReL2BvqqA3oEcAa7txju5GY6G4nxJ51zvsEjEZ
  f->prevent_calling_precompiles_as_programs = 1; // 4ApgRX3ud6p7LNMJmsuaAcZY5HWctGPr5obAsjB3A54d
  f->prevent_crediting_accounts_that_end_rent_paying = 1; // 812kqX67odAp5NFwM8D2N24cku7WTm9CHUTFUXaDkWPn
  f->prevent_rent_paying_rent_recipients = 1; // Fab5oP3DmsLYCiQZXdjyqT3ukFFPrsmqhXU4WU1AWVVF
  f->quick_bail_on_panic = 1; // DpJREPyuMZ5nDfU6H3WTqSqUFSXAfw8u7xqmWtEwJDcP
  f->record_instruction_in_transaction_context_push = 1; // 3aJdcZqxoLpSBxgeYGjPwaYS1zzcByxUDqJkbzWAH1Zb
  f->reduce_required_deploy_balance = 1; // EBeznQDjcPG8491sFsKZYBi5S5jTVXMpAKNDJMQPS2kq
  f->reject_callx_r10 = 1; // 3NKRSwpySNwD3TvP5pHnRmkAQRsdkXWRr1WaQh8p4PWX
  f->reject_empty_instruction_without_program = 1; // 9kdtFSrXHQg3hKkbXkQ6trJ3Ja1xpJ22CTFSNAciEwmL
  f->reject_non_rent_exempt_vote_withdraws = 1; // 7txXZZD6Um59YoLMF7XUNimbMjsqsWhc7g2EniiTrmp1
  f->reject_vote_account_close_unless_zero_credit_epoch = 1; // ALBk3EWdeAg2WAGf6GPDUf1nynyNqCdEVmgouG7rpuCj
  f->relax_authority_signer_check_for_lookup_table_creation = 1; // FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap
  f->remove_bpf_loader_incorrect_program_id = 1; // 2HmTkCj9tXuPE4ueHzdD7jPeMf9JGCoZh5AsyoATiWEe
  f->remove_congestion_multiplier_from_fee_calculation = 1; // A8xyMHZovGXFkorFqEmVH2PKGLiBip5JD7jt4zsUWo4H
  f->remove_deprecated_request_unit_ix = 1; // EfhYd3SafzGT472tYQDUc4dPd2xdEfKs5fwkowUgVt4W
  f->remove_native_loader = 1; // HTTgmruMYRZEntyL3EdCDdnS6e4D5wRq1FA7kQsb66qq
  f->rent_for_sysvars = 1; // BKCPBQQBZqggVnFso5nQ8rQ4RwwogYwjuUt9biBjxwNF
  f->requestable_heap_size = 1; // CCu4boMmfLuqcmfTLPHQiUo22ZdUsXjgzPAURYaWt1Bw
  f->require_custodian_for_locked_stake_authorize = 1; // D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R
  f->require_rent_exempt_accounts = 1; // BkFDxiJQWZXGTZaJQxH7wVEHkAmwCgSEVkrvswFfRJPD
  f->require_static_program_ids_in_transaction = 1; // 8FdwgyHFEjhAdjWfV2vfqk7wA1g9X3fQpKH7SBpEv3kC
  f->return_data_syscall_enabled = 1; // DwScAzPUjuv65TMbDnFY7AgwmotzWy3xpEJMXM3hZFaB
  f->round_up_heap_size = 1; // CE2et8pqgyQMP2mQRg3CgvX8nJBKUArMu3wfiQiQKY1y
  f->secp256k1_program_enabled = 1; // E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y
  f->secp256k1_recover_syscall_enabled = 1; // 6RvdSWHh8oh72Dp7wMTS2DBkf3fRPtChfNrAo3cZZoXJ
  f->send_to_tpu_vote_port = 1; // C5fh68nJ7uyKAuYZg2x9sEQ5YrVf3dkW6oojNBSc3Jvo
  f->separate_nonce_from_blockhash = 1; // Gea3ZkK2N4pHuVZVxWcnAtS6UEDdyumdYt4pFcKjA3ar
  f->set_exempt_rent_epoch_max = 1; // 5wAGiy15X1Jb2hkHnPDCM8oB9V42VNA9ftNVFK84dEgv
  f->simplify_writable_program_account_check = 1; // 5ZCcFAzJ1zsFKe1KSZa9K92jhx7gkcKj97ci2DBo1vwj
  f->skip_rent_rewrites = 1; // CGB2jM8pwZkeeiXQ66kBMyBR6Np61mggL7XUsmLjVcrw
  f->sol_log_data_syscall_enabled = 1; // 6uaHcKPGUy4J7emLBgUTeufhJdiwhngW6a1R9B7c2ob9
  f->spl_associated_token_account_v1_0_4 = 1; // FaTa4SpiaSNH44PGC4z8bnGVTkSRYaWvrBs3KTu8XQQq
  f->spl_associated_token_account_v1_1_0 = 1; // FaTa17gVKoqbh38HcfiQonPsAaQViyDCCSg71AubYZw8
  f->spl_token_v2_multisig_fix = 1; // E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv
  f->spl_token_v2_self_transfer_fix = 1; // BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7
  f->spl_token_v2_set_authority_fix = 1; // FToKNBYyiF4ky9s8WsmLBXHCht17Ek7RXaLZGHzzQhJ1
  f->spl_token_v3_3_0_release = 1; // Ftok2jhqAqxUWEiCVRrfRs9DPppWP8cgTB7NQNKL88mS
  f->spl_token_v3_4_0 = 1; // Ftok4njE8b7tDffYkC5bAbCaQv5sL6jispYrprzatUwN
  f->stake_allow_zero_undelegated_amount = 1; // sTKz343FM8mqtyGvYWvbLpTThw3ixRM4Xk8QvZ985mw
  f->stake_deactivate_delinquent_instruction = 1; // 437r62HoAdUb63amq3D7ENnBLDhHT2xY8eFkLJYVKK4x
  f->stake_merge_with_unmatched_credits_observed = 1; // meRgp4ArRPhD3KtCY9c5yAf2med7mBLsjKTPeVUHqBL
  f->stake_minimum_delegation_for_rewards = 1; // ELjxSXwNsyXGfAh8TqX8ih22xeT8huF6UngQirbLKYKH
  f->stake_program_advance_activating_credits_observed = 1; // SAdVFw3RZvzbo6DvySbSdBnHN4gkzSTH9dSxesyKKPj
  f->stake_raise_minimum_delegation_to_1_sol = 1; // 9onWzzvCzNC2jfhxxeqRgs5q7nFAAKpCUvkj6T6GJK9i
  f->stake_redelegate_instruction = 1; // 3EPmAX94PvVJCjMeFfRFvj4avqCPL8vv3TGsZQg7ydMx
  f->stake_split_uses_rent_sysvar = 1; // FQnc7U4koHqWgRvFaBJjZnV8VPg6L6wWK33yJeDp4yvV
  f->stakes_remove_delegation_if_inactive = 1; // HFpdDDNQjvcXnXKec697HDDsyk6tFoWS2o8fkxuhQZpL
  f->stop_sibling_instruction_search_at_parent = 1; // EYVpEP7uzH1CoXzbD6PubGhYmnxRXPeq3PPsm1ba3gpo
  f->stop_truncating_strings_in_syscalls = 1; // 16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg
  f->switch_to_new_elf_parser = 1; // Cdkc8PPTeTNUPoZEfCY5AyetUrEdkZtNPMgz58nqyaHD
  f->syscall_saturated_math = 1; // HyrbKftCdJ5CrUfEti6x26Cj7rZLNe32weugk7tLcWb8
  f->system_transfer_zero_check = 1; // BrTR9hzw4WBGFP65AJMbpAo64DcA3U6jdPSga9fMV5cS
  f->tx_wide_compute_cap = 1; // 5ekBxc8itEnPv4NzGJtr8BVVQLNMQuLMNQQj7pHoLNZ9
  f->update_hashes_per_tick = 1; // 3uFHb9oKdGfgZGJK9EHaAXN4USvnQtAFC13Fh5gGFS5B
  f->update_rewards_from_cached_accounts = 1; // 28s7i3htzhahXQKqmS2ExzbEoUypg9krwvtK2M9UWXh9
  f->update_syscall_base_costs = 1; // 2h63t332mGCCsWK2nqqqHhN4U9ayyqhLVFvczznHDoTZ
  f->use_default_units_in_fee_calculation = 1; // 8sKQrMQoUHtQSUP83SPG4ta2JDjSAiWs7t5aJ9uEd6To
  f->verify_tx_signatures_len = 1; // EVW9B5xD9FFK7vw1SBARwMA4s5eRo5eKJdKpsBikzKBz
  f->versioned_tx_message_enabled = 1; // 3KZZ6Ks1885aGBQ45fwRcPXVBCtzUvxhUTkwKMR41Tca
  f->vote_authorize_with_seed = 1; // 6tRxEYKuy2L5nnv5bgn7iT28MxUbYxp5h7F3Ncf1exrT
  f->vote_stake_checked_instructions = 1; // BcWknVcgvonN8sL4HE4XFuEVgfcee5MwxWPAgP6ZV89X
  f->vote_state_add_vote_latency = 1; // 7axKe5BTYBDD87ftzWbk5DfzWMGyRvqmWTduuo22Yaqy
  f->vote_state_update_credit_per_dequeue = 1; // CveezY6FDLVBToHDcvJRmtMouqzsmj4UXYh5ths5G5Uv
  f->vote_state_update_root_fix = 1; // G74BkWBzmsByZ1kxHy44H3wjwp5hp7JbrGRuDpco22tY
  f->vote_withdraw_authority_may_change_authorized_voter = 1; // AVZS3ZsN4gi6Rkx2QUibYuSJG3S6QHib7xCYhG6vGJxU
  f->warp_timestamp_again = 1; // GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb
  f->warp_timestamp_with_a_vengeance = 1; // 3BX6SBeEBibHaVQXywdkcgyUk6evfYZkHdztXiDtEpFS
  f->zk_token_sdk_enabled = 1; // zk1snxsc6Fh3wsGNbbHAJNHiJoYgF29mMnTSusGx5EJ
}
void fd_update_features(fd_global_ctx_t * global) {
  fd_update_feature(global, &global->features.secp256k1_program_enabled, "E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y");
  fd_update_feature(global, &global->features.spl_token_v2_multisig_fix, "E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv");
  fd_update_feature(global, &global->features.no_overflow_rent_distribution, "4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz");
  fd_update_feature(global, &global->features.deprecate_rewards_sysvar, "GaBtBJvmS4Arjj5W1NmFcyvPjsHN38UGYDq2MDwbs9Qu");
  fd_update_feature(global, &global->features.pico_inflation, "4RWNif6C2WCNiKVW7otP4G7dkmkHGyKQWRpuZ1pxKU5m");
  fd_update_feature(global, &global->features.filter_stake_delegation_accounts, "GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi");
  fd_update_feature(global, &global->features.full_inflation_mainnet_certusoneenable, "7XRJcS5Ud5vxGB54JbK9N2vBZVwnwdBNeJW1ibRgD9gx");
  fd_update_feature(global, &global->features.full_inflation_mainnet_certusone_vote, "BzBBveUDymEYoYzcMWNQCx3cd4jQs7puaVFHLtsbB6fm");
  fd_update_feature(global, &global->features.spl_token_v2_self_transfer_fix, "BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7");
  fd_update_feature(global, &global->features.warp_timestamp_again, "GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb");
  fd_update_feature(global, &global->features.check_init_vote_data, "3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F");
  fd_update_feature(global, &global->features.require_custodian_for_locked_stake_authorize, "D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R");
  fd_update_feature(global, &global->features.vote_stake_checked_instructions, "BcWknVcgvonN8sL4HE4XFuEVgfcee5MwxWPAgP6ZV89X");
  fd_update_feature(global, &global->features.system_transfer_zero_check, "BrTR9hzw4WBGFP65AJMbpAo64DcA3U6jdPSga9fMV5cS");
  fd_update_feature(global, &global->features.spl_token_v2_set_authority_fix, "FToKNBYyiF4ky9s8WsmLBXHCht17Ek7RXaLZGHzzQhJ1");
  fd_update_feature(global, &global->features.demote_program_write_locks, "3E3jV7v9VcdJL8iYZUMax9DiDno8j7EWUVbhm9RtShj2");
  fd_update_feature(global, &global->features.send_to_tpu_vote_port, "C5fh68nJ7uyKAuYZg2x9sEQ5YrVf3dkW6oojNBSc3Jvo");
  fd_update_feature(global, &global->features.reduce_required_deploy_balance, "EBeznQDjcPG8491sFsKZYBi5S5jTVXMpAKNDJMQPS2kq");
  fd_update_feature(global, &global->features.verify_tx_signatures_len, "EVW9B5xD9FFK7vw1SBARwMA4s5eRo5eKJdKpsBikzKBz");
  fd_update_feature(global, &global->features.stake_program_advance_activating_credits_observed, "SAdVFw3RZvzbo6DvySbSdBnHN4gkzSTH9dSxesyKKPj");
  fd_update_feature(global, &global->features.stake_merge_with_unmatched_credits_observed, "meRgp4ArRPhD3KtCY9c5yAf2med7mBLsjKTPeVUHqBL");
  fd_update_feature(global, &global->features.secp256k1_recover_syscall_enabled, "6RvdSWHh8oh72Dp7wMTS2DBkf3fRPtChfNrAo3cZZoXJ");
  fd_update_feature(global, &global->features.rent_for_sysvars, "BKCPBQQBZqggVnFso5nQ8rQ4RwwogYwjuUt9biBjxwNF");
  fd_update_feature(global, &global->features.optimize_epoch_boundary_updates, "265hPS8k8xJ37ot82KEgjRunsUp5w4n4Q4VwwiN9i9ps");
  fd_update_feature(global, &global->features.dedupe_config_program_signers, "8kEuAshXLsgkUEdcFVLqrjCGGHVWFW99ZZpxvAzzMtBp");
  fd_update_feature(global, &global->features.libsecp256k1_0_5_upgrade_enabled, "DhsYfRjxfnh2g7HKJYSzT79r74Afa1wbHkAgHndrA1oy");
  fd_update_feature(global, &global->features.stakes_remove_delegation_if_inactive, "HFpdDDNQjvcXnXKec697HDDsyk6tFoWS2o8fkxuhQZpL");
  fd_update_feature(global, &global->features.add_compute_budget_program, "4d5AKtxoh93Dwm1vHXUU3iRATuMndx1c431KgT2td52r");
  fd_update_feature(global, &global->features.reject_non_rent_exempt_vote_withdraws, "7txXZZD6Um59YoLMF7XUNimbMjsqsWhc7g2EniiTrmp1");
  fd_update_feature(global, &global->features.evict_invalid_stakes_cache_entries, "EMX9Q7TVFAmQ9V1CggAkhMzhXSg8ECp7fHrWQX2G1chf");
  fd_update_feature(global, &global->features.spl_token_v3_3_0_release, "Ftok2jhqAqxUWEiCVRrfRs9DPppWP8cgTB7NQNKL88mS");
  fd_update_feature(global, &global->features.remove_native_loader, "HTTgmruMYRZEntyL3EdCDdnS6e4D5wRq1FA7kQsb66qq");
  fd_update_feature(global, &global->features.ed25519_program_enabled, "6ppMXNYLhVd7GcsZ5uV11wQEW7spppiMVfqQv5SXhDpX");
  fd_update_feature(global, &global->features.sol_log_data_syscall_enabled, "6uaHcKPGUy4J7emLBgUTeufhJdiwhngW6a1R9B7c2ob9");
  fd_update_feature(global, &global->features.return_data_syscall_enabled, "DwScAzPUjuv65TMbDnFY7AgwmotzWy3xpEJMXM3hZFaB");
  fd_update_feature(global, &global->features.spl_associated_token_account_v1_0_4, "FaTa4SpiaSNH44PGC4z8bnGVTkSRYaWvrBs3KTu8XQQq");
  fd_update_feature(global, &global->features.leave_nonce_on_success, "E8MkiWZNNPGU6n55jkGzyj8ghUmjCHRmDFdYYFYHxWhQ");
  fd_update_feature(global, &global->features.require_rent_exempt_accounts, "BkFDxiJQWZXGTZaJQxH7wVEHkAmwCgSEVkrvswFfRJPD");
  fd_update_feature(global, &global->features.do_support_realloc, "75m6ysz33AfLA5DDEzWM1obBrnPQRSsdVQ2nRmc8Vuu1");
  fd_update_feature(global, &global->features.add_get_processed_sibling_instruction_syscall, "CFK1hRCNy8JJuAAY8Pb2GjLFNdCThS2qwZNe3izzBMgn");
  fd_update_feature(global, &global->features.tx_wide_compute_cap, "5ekBxc8itEnPv4NzGJtr8BVVQLNMQuLMNQQj7pHoLNZ9");
  fd_update_feature(global, &global->features.requestable_heap_size, "CCu4boMmfLuqcmfTLPHQiUo22ZdUsXjgzPAURYaWt1Bw");
  fd_update_feature(global, &global->features.warp_timestamp_with_a_vengeance, "3BX6SBeEBibHaVQXywdkcgyUk6evfYZkHdztXiDtEpFS");
  fd_update_feature(global, &global->features.nonce_must_be_writable, "BiCU7M5w8ZCMykVSyhZ7Q3m2SWoR2qrEQ86ERcDX77ME");
  fd_update_feature(global, &global->features.reject_empty_instruction_without_program, "9kdtFSrXHQg3hKkbXkQ6trJ3Ja1xpJ22CTFSNAciEwmL");
  fd_update_feature(global, &global->features.add_shred_type_to_shred_seed, "Ds87KVeqhbv7Jw8W6avsS1mqz3Mw5J3pRTpPoDQ2QdiJ");
  fd_update_feature(global, &global->features.fixed_memcpy_nonoverlapping_check, "36PRUK2Dz6HWYdG9SpjeAsF5F3KxnFCakA2BZMbtMhSb");
  fd_update_feature(global, &global->features.nonce_must_be_advanceable, "3u3Er5Vc2jVcwz4xr2GJeSAXT3fAj6ADHZ4BJMZiScFd");
  fd_update_feature(global, &global->features.enable_durable_nonce, "4EJQtF2pkRyawwcTVfQutzq4Sa5hRhibF6QAK1QXhtEX");
  fd_update_feature(global, &global->features.separate_nonce_from_blockhash, "Gea3ZkK2N4pHuVZVxWcnAtS6UEDdyumdYt4pFcKjA3ar");
  fd_update_feature(global, &global->features.nonce_must_be_authorized, "HxrEu1gXuH7iD3Puua1ohd5n4iUKJyFNtNxk9DVJkvgr");
  fd_update_feature(global, &global->features.update_syscall_base_costs, "2h63t332mGCCsWK2nqqqHhN4U9ayyqhLVFvczznHDoTZ");
  fd_update_feature(global, &global->features.vote_withdraw_authority_may_change_authorized_voter, "AVZS3ZsN4gi6Rkx2QUibYuSJG3S6QHib7xCYhG6vGJxU");
  fd_update_feature(global, &global->features.disable_bpf_deprecated_load_instructions, "3XgNukcZWf9o3HdA3fpJbm94XFc4qpvTXc8h1wxYwiPi");
  fd_update_feature(global, &global->features.disable_bpf_unresolved_symbols_at_runtime, "4yuaYAj2jGMGTh1sSmi4G2eFscsDq8qjugJXZoBN6YEa");
  fd_update_feature(global, &global->features.executables_incur_cpi_data_cost, "7GUcYgq4tVtaqNCKT3dho9r4665Qp5TxCZ27Qgjx3829");
  fd_update_feature(global, &global->features.max_tx_account_locks, "CBkDroRDqm8HwHe6ak9cguPjUomrASEkfmxEaZ5CNNxz");
  fd_update_feature(global, &global->features.quick_bail_on_panic, "DpJREPyuMZ5nDfU6H3WTqSqUFSXAfw8u7xqmWtEwJDcP");
  fd_update_feature(global, &global->features.default_units_per_instruction, "J2QdYx8crLbTVK8nur1jeLsmc3krDbfjoxoea2V1Uy5Q");
  fd_update_feature(global, &global->features.record_instruction_in_transaction_context_push, "3aJdcZqxoLpSBxgeYGjPwaYS1zzcByxUDqJkbzWAH1Zb");
  fd_update_feature(global, &global->features.add_set_compute_unit_price_ix, "98std1NSHqXi9WYvFShfVepRdCoq1qvsp8fsR2XZtG8g");
  fd_update_feature(global, &global->features.limit_secp256k1_recovery_id, "7g9EUwj4j7CS21Yx1wvgWLjSZeh5aPq8x9kpoPwXM8n8");
  fd_update_feature(global, &global->features.check_physical_overlapping, "nWBqjr3gpETbiaVj3CBJ3HFC5TMdnJDGt21hnvSTvVZ");
  fd_update_feature(global, &global->features.prevent_calling_precompiles_as_programs, "4ApgRX3ud6p7LNMJmsuaAcZY5HWctGPr5obAsjB3A54d");
  fd_update_feature(global, &global->features.spl_associated_token_account_v1_1_0, "FaTa17gVKoqbh38HcfiQonPsAaQViyDCCSg71AubYZw8");
  fd_update_feature(global, &global->features.spl_token_v3_4_0, "Ftok4njE8b7tDffYkC5bAbCaQv5sL6jispYrprzatUwN");
  fd_update_feature(global, &global->features.disable_fee_calculator, "2jXx2yDmGysmBKfKYNgLj2DQyAQv6mMk2BPh4eSbyB4H");
  fd_update_feature(global, &global->features.vote_authorize_with_seed, "6tRxEYKuy2L5nnv5bgn7iT28MxUbYxp5h7F3Ncf1exrT");
  fd_update_feature(global, &global->features.syscall_saturated_math, "HyrbKftCdJ5CrUfEti6x26Cj7rZLNe32weugk7tLcWb8");
  fd_update_feature(global, &global->features.merge_nonce_error_into_system_error, "21AWDosvp3pBamFW91KB35pNoaoZVTM7ess8nr2nt53B");
  fd_update_feature(global, &global->features.instructions_sysvar_owned_by_sysvar, "H3kBSaKdeiUsyHmeHqjJYNc27jesXZ6zWj3zWkowQbkV");
  fd_update_feature(global, &global->features.require_static_program_ids_in_transaction, "8FdwgyHFEjhAdjWfV2vfqk7wA1g9X3fQpKH7SBpEv3kC");
  fd_update_feature(global, &global->features.include_account_index_in_rent_error, "2R72wpcQ7qV7aTJWUumdn8u5wmmTyXbK7qzEy7YSAgyY");
  fd_update_feature(global, &global->features.versioned_tx_message_enabled, "3KZZ6Ks1885aGBQ45fwRcPXVBCtzUvxhUTkwKMR41Tca");
  fd_update_feature(global, &global->features.preserve_rent_epoch_for_rent_exempt_accounts, "HH3MUYReL2BvqqA3oEcAa7txju5GY6G4nxJ51zvsEjEZ");
  fd_update_feature(global, &global->features.filter_votes_outside_slot_hashes, "3gtZPqvPpsbXZVCx6hceMfWxtsmrjMzmg8C7PLKSxS2d");
  fd_update_feature(global, &global->features.prevent_crediting_accounts_that_end_rent_paying, "812kqX67odAp5NFwM8D2N24cku7WTm9CHUTFUXaDkWPn");
  fd_update_feature(global, &global->features.disable_deprecated_loader, "GTUMCZ8LTNxVfxdrw7ZsDFTxXb7TutYkzJnFwinpE6dg");
  fd_update_feature(global, &global->features.reject_vote_account_close_unless_zero_credit_epoch, "ALBk3EWdeAg2WAGf6GPDUf1nynyNqCdEVmgouG7rpuCj");
  fd_update_feature(global, &global->features.bank_transaction_count_fix, "Vo5siZ442SaZBKPXNocthiXysNviW4UYPwRFggmbgAp");
  fd_update_feature(global, &global->features.check_syscall_outputs_do_not_overlap, "3uRVPBpyEJRo1emLCrq38eLRFGcu6uKSpUXqGvU8T7SZ");
  fd_update_feature(global, &global->features.stake_deactivate_delinquent_instruction, "437r62HoAdUb63amq3D7ENnBLDhHT2xY8eFkLJYVKK4x");
  fd_update_feature(global, &global->features.drop_redundant_turbine_path, "4Di3y24QFLt5QEUPZtbnjyfQKfm6ZMTfa6Dw1psfoMKU");
  fd_update_feature(global, &global->features.add_get_minimum_delegation_instruction_to_stake_program, "St8k9dVXP97xT6faW24YmRSYConLbhsMJA4TJTBLmMT");
  fd_update_feature(global, &global->features.stake_allow_zero_undelegated_amount, "sTKz343FM8mqtyGvYWvbLpTThw3ixRM4Xk8QvZ985mw");
  fd_update_feature(global, &global->features.credits_auto_rewind, "BUS12ciZ5gCoFafUHWW8qaFMMtwFQGVxjsDheWLdqBE2");
  fd_update_feature(global, &global->features.libsecp256k1_fail_on_bad_count2, "54KAoNiUERNoWWUhTWWwXgym94gzoXFVnHyQwPA18V9A");
  fd_update_feature(global, &global->features.vote_state_update_root_fix, "G74BkWBzmsByZ1kxHy44H3wjwp5hp7JbrGRuDpco22tY");
  fd_update_feature(global, &global->features.move_serialized_len_ptr_in_cpi, "74CoWuBmt3rUVUrCb2JiSTvh6nXyBWUsK4SaMj3CtE3T");
  fd_update_feature(global, &global->features.stake_split_uses_rent_sysvar, "FQnc7U4koHqWgRvFaBJjZnV8VPg6L6wWK33yJeDp4yvV");
  fd_update_feature(global, &global->features.on_load_preserve_rent_epoch_for_rent_exempt_accounts, "CpkdQmspsaZZ8FVAouQTtTWZkc8eeQ7V3uj7dWz543rZ");
  fd_update_feature(global, &global->features.disable_rehash_for_rent_epoch, "DTVTkmw3JSofd8CJVJte8PXEbxNQ2yZijvVr3pe2APPj");
  fd_update_feature(global, &global->features.fix_recent_blockhashes, "6iyggb5MTcsvdcugX7bEKbHV8c6jdLbpHwkncrgLMhfo");
  fd_update_feature(global, &global->features.cap_bpf_program_instruction_accounts, "9k5ijzTbYPtjzu8wj2ErH9v45xecHzQ1x4PMYMMxFgdM");
  fd_update_feature(global, &global->features.update_rewards_from_cached_accounts, "28s7i3htzhahXQKqmS2ExzbEoUypg9krwvtK2M9UWXh9");
  fd_update_feature(global, &global->features.use_default_units_in_fee_calculation, "8sKQrMQoUHtQSUP83SPG4ta2JDjSAiWs7t5aJ9uEd6To");
  fd_update_feature(global, &global->features.disable_builtin_loader_ownership_chains, "4UDcAfQ6EcA6bdcadkeHpkarkhZGJ7Bpq7wTAiRMjkoi");
  fd_update_feature(global, &global->features.check_slice_translation_size, "GmC19j9qLn2RFk5NduX6QXaDhVpGncVVBzyM8e9WMz2F");
  fd_update_feature(global, &global->features.disable_fees_sysvar, "JAN1trEUEtZjgXYzNBYHU9DYd7GnThhXfFP7SzPXkPsG");
  fd_update_feature(global, &global->features.stop_truncating_strings_in_syscalls, "16FMCmgLzCNNz6eTwGanbyN2ZxvTBSLuQ6DZhgeMshg");
  fd_update_feature(global, &global->features.incremental_snapshot_only_incremental_hash_calculation, "25vqsfjk7Nv1prsQJmA4Xu1bN61s8LXCBGUPp8Rfy1UF");
  fd_update_feature(global, &global->features.remove_bpf_loader_incorrect_program_id, "2HmTkCj9tXuPE4ueHzdD7jPeMf9JGCoZh5AsyoATiWEe");
  fd_update_feature(global, &global->features.apply_cost_tracker_during_replay, "2ry7ygxiYURULZCrypHhveanvP5tzZ4toRwVp89oCNSj");
  fd_update_feature(global, &global->features.stake_redelegate_instruction, "3EPmAX94PvVJCjMeFfRFvj4avqCPL8vv3TGsZQg7ydMx");
  fd_update_feature(global, &global->features.reject_callx_r10, "3NKRSwpySNwD3TvP5pHnRmkAQRsdkXWRr1WaQh8p4PWX");
  fd_update_feature(global, &global->features.update_hashes_per_tick, "3uFHb9oKdGfgZGJK9EHaAXN4USvnQtAFC13Fh5gGFS5B");
  fd_update_feature(global, &global->features.epoch_accounts_hash, "5GpmAKxaGsWWbPp4bNXFLJxZVvG92ctxf7jQnzTQjF3n");
  fd_update_feature(global, &global->features.checked_arithmetic_in_fee_validation, "5Pecy6ie6XGm22pc9d4P9W5c31BugcFBuy6hsP2zkETv");
  fd_update_feature(global, &global->features.simplify_writable_program_account_check, "5ZCcFAzJ1zsFKe1KSZa9K92jhx7gkcKj97ci2DBo1vwj");
  fd_update_feature(global, &global->features.set_exempt_rent_epoch_max, "5wAGiy15X1Jb2hkHnPDCM8oB9V42VNA9ftNVFK84dEgv");
  fd_update_feature(global, &global->features.enable_bpf_loader_set_authority_checked_ix, "5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL");
  fd_update_feature(global, &global->features.disable_deploy_of_alloc_free_syscall, "79HWsX9rpnnJBPcdNURVqygpMAfxdrAirzAGAVmf92im");
  fd_update_feature(global, &global->features.enable_early_verification_of_account_modifications, "7Vced912WrRnfjaiKRiNBcbuFw7RrnLv3E3z95Y4GTNc");
  fd_update_feature(global, &global->features.vote_state_add_vote_latency, "7axKe5BTYBDD87ftzWbk5DfzWMGyRvqmWTduuo22Yaqy");
  fd_update_feature(global, &global->features.curve25519_syscall_enabled, "7rcw5UtqgDTBBv2EcynNfYckgdAaH1MAsCjKgXMkN7Ri");
  fd_update_feature(global, &global->features.error_on_syscall_bpf_function_hash_collisions, "8199Q2gMD2kwgfopK5qqVWuDbegLgpuFUFHCcUJQDN8b");
  fd_update_feature(global, &global->features.drop_merkle_shreds, "84zy5N23Q9vTZuLc9h1HWUtyM9yCFV2SCmyP9W9C3yHZ");
  fd_update_feature(global, &global->features.compact_vote_state_updates, "86HpNqzutEZwLcPxS6EHDcMNYWk6ikhteg9un7Y2PBKE");
  fd_update_feature(global, &global->features.enable_bpf_loader_extend_program_ix, "8Zs9W7D9MpSEtUWSQdGniZk2cNmV22y6FLJwCx53asme");
  fd_update_feature(global, &global->features.libsecp256k1_fail_on_bad_count, "8aXvSuopd1PUj7UhehfXJRg6619RHp8ZvwTyyJHdUYsj");
  fd_update_feature(global, &global->features.native_programs_consume_cu, "8pgXCMNXC8qyEFypuwpXyRxLXZdpM4Qo72gJ6k87A6wL");
  fd_update_feature(global, &global->features.increase_tx_account_lock_limit, "9LZdXeKGeBV6hRLdxS1rHbHoEUsKqesCC2ZAPTPKJAbK");
  fd_update_feature(global, &global->features.bpf_account_data_direct_mapping, "9gwzizfABsKUereT6phZZxbTzuAnovkgwpVVpdcSxv9h");
  fd_update_feature(global, &global->features.cap_accounts_data_allocations_per_transaction, "9gxu85LYRAcZL38We8MYJ4A9AwgBBPtVBAqebMcT1241");
  fd_update_feature(global, &global->features.stake_raise_minimum_delegation_to_1_sol, "9onWzzvCzNC2jfhxxeqRgs5q7nFAAKpCUvkj6T6GJK9i");
  fd_update_feature(global, &global->features.enable_alt_bn128_syscall, "A16q37opZdQMCbe5qJ6xpBB9usykfv8jZaMkxvZQi4GJ");
  fd_update_feature(global, &global->features.remove_congestion_multiplier_from_fee_calculation, "A8xyMHZovGXFkorFqEmVH2PKGLiBip5JD7jt4zsUWo4H");
  fd_update_feature(global, &global->features.disable_cpi_setting_executable_and_rent_epoch, "B9cdB55u4jQsDNsdTK525yE9dmSc5Ga7YBaBrDFvEhM9");
  fd_update_feature(global, &global->features.clean_up_delegation_errors, "Bj2jmUsM2iRhfdLLDSTkhM5UQRQvQHm57HSmPibPtEyu");
  fd_update_feature(global, &global->features.round_up_heap_size, "CE2et8pqgyQMP2mQRg3CgvX8nJBKUArMu3wfiQiQKY1y");
  fd_update_feature(global, &global->features.skip_rent_rewrites, "CGB2jM8pwZkeeiXQ66kBMyBR6Np61mggL7XUsmLjVcrw");
  fd_update_feature(global, &global->features.switch_to_new_elf_parser, "Cdkc8PPTeTNUPoZEfCY5AyetUrEdkZtNPMgz58nqyaHD");
  fd_update_feature(global, &global->features.vote_state_update_credit_per_dequeue, "CveezY6FDLVBToHDcvJRmtMouqzsmj4UXYh5ths5G5Uv");
  fd_update_feature(global, &global->features.enable_turbine_fanout_experiments, "D31EFnLgdiysi84Woo3of4JMu7VmasUS3Z7j9HYXCeLY");
  fd_update_feature(global, &global->features.full_inflation_devnet_and_testnet, "DT4n6ABDqs6w4bnfwrXT9rsprcPf6cdDga1egctaPkLC");
  fd_update_feature(global, &global->features.cap_transaction_accounts_data_size, "DdLwVYuvDz26JohmgSbA7mjpJFgX5zP2dkp8qsF2C33V");
  fd_update_feature(global, &global->features.enable_big_mod_exp_syscall, "EBq48m8irRKuE7ZnMTLvLg2UuGSqhe8s8oMqnmja1fJw");
  fd_update_feature(global, &global->features.stake_minimum_delegation_for_rewards, "ELjxSXwNsyXGfAh8TqX8ih22xeT8huF6UngQirbLKYKH");
  fd_update_feature(global, &global->features.stop_sibling_instruction_search_at_parent, "EYVpEP7uzH1CoXzbD6PubGhYmnxRXPeq3PPsm1ba3gpo");
  fd_update_feature(global, &global->features.include_loaded_accounts_data_size_in_fee_calculation, "EaQpmC6GtRssaZ3PCUM5YksGqUdMLeZ46BQXYtHYakDS");
  fd_update_feature(global, &global->features.remove_deprecated_request_unit_ix, "EfhYd3SafzGT472tYQDUc4dPd2xdEfKs5fwkowUgVt4W");
  fd_update_feature(global, &global->features.relax_authority_signer_check_for_lookup_table_creation, "FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap");
  fd_update_feature(global, &global->features.prevent_rent_paying_rent_recipients, "Fab5oP3DmsLYCiQZXdjyqT3ukFFPrsmqhXU4WU1AWVVF");
  fd_update_feature(global, &global->features.allow_votes_to_directly_update_vote_state, "Ff8b1fBeB86q8cjq47ZhsQLgv5EkHu3G1C99zjUfAzrq");
  fd_update_feature(global, &global->features.add_set_tx_loaded_accounts_data_size_instruction, "G6vbf1UBok8MWb8m25ex86aoQHeKTzDKzuZADHkShqm6");
  fd_update_feature(global, &global->features.loosen_cpi_size_restriction, "GDH5TVdbTPUpRnXaRyQqiKUa7uZAbZ28Q2N9bhbKoMLm");
  fd_update_feature(global, &global->features.limit_max_instruction_trace_length, "GQALDaC48fEhZGWRj9iL5Q889emJKcj3aCvHF7VCbbF4");
  fd_update_feature(global, &global->features.delay_visibility_of_program_deployment, "GmuBvtFb2aHfSfMXpuFeWZGHyDeCLPS79s48fmCWCfM5");
  fd_update_feature(global, &global->features.disable_turbine_fanout_experiments, "Gz1aLrbeQ4Q6PTSafCZcGWZXz91yVRi7ASFzFEr1U4sa");
  fd_update_feature(global, &global->features.enable_partitioned_epoch_reward, "HCnE3xQoZtDz9dSVm3jKwJXioTb6zMRbgwCmGg3PHHk8");
  fd_update_feature(global, &global->features.blake3_syscall_enabled, "HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3");
  fd_update_feature(global, &global->features.last_restart_slot_sysvar, "HooKD5NC9QNxk25QuzCssB8ecrEzGt6eXEPBUxWp1LaR");
  fd_update_feature(global, &global->features.enable_request_heap_frame_ix, "Hr1nUA9b7NJ6eChS26o7Vi8gYYDDwWD3YeBfzJkTbU86");
  fd_update_feature(global, &global->features.keep_merkle_shreds, "HyNQzc7TMNmRhpVHXqDGjpsHzeQie82mDQXSF9hj7nAH");
  fd_update_feature(global, &global->features.enable_program_redeployment_cooldown, "J4HFT8usBxpcF63y46t1upYobJgChmKyZPm5uTBRg25Z");
  fd_update_feature(global, &global->features.account_hash_ignore_slot, "SVn36yVApPLYsa8koK3qUcy14zXDnqkNYWyUh1f4oK1");
  fd_update_feature(global, &global->features.cap_accounts_data_len, "capRxUrBjNkkCpjrJxPGfPaWijB7q3JoDfsWXAnt46r");
  fd_update_feature(global, &global->features.commission_updates_only_allowed_in_first_half_of_epoch, "noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp");
  fd_update_feature(global, &global->features.cap_accounts_data_size_per_block, "qywiJyZmqTKspFg2LeuUHqcA5nNvBgobqb9UprywS9N");
  fd_update_feature(global, &global->features.zk_token_sdk_enabled, "zk1snxsc6Fh3wsGNbbHAJNHiJoYgF29mMnTSusGx5EJ");
}
