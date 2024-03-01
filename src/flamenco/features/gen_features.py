#!/usr/bin/env python3

"""
gen_features.py auto-generates fd_features_generated.{h,c} from
feature_map.json.
"""

import argparse
import json
from pathlib import Path
import struct
from base58 import b58decode

# The list of all feature names whose implementation has been removed from the Solana source code, and which therefore should default to enabled
REMOVED_FEATURES = [
    'secp256k1_program_enabled',
    'spl_token_v2_multisig_fix',
    'filter_stake_delegation_accounts',
    'spl_token_v2_self_transfer_fix',
    'check_init_vote_data',
    'secp256k1_recover_syscall_enabled',
    'verify_tx_signatures_len',
    'rent_for_sysvars',
    'tx_wide_compute_cap',
    'spl_token_v2_set_authority_fix',
    'merge_nonce_error_into_system_error',
    'versioned_tx_message_enabled',
    'instructions_sysvar_owned_by_sysvar',
    'stake_program_advance_activating_credits_observed',
    'credits_auto_rewind',
    'demote_program_write_locks',
    'ed25519_program_enabled',
    'return_data_syscall_enabled',
    'reduce_required_deploy_balance',
    'sol_log_data_syscall_enabled',
    'stakes_remove_delegation_if_inactive',
    'do_support_realloc',
    'prevent_calling_precompiles_as_programs',
    'optimize_epoch_boundary_updates',
    'remove_native_loader',
    'send_to_tpu_vote_port',
    'requestable_heap_size',
    'disable_fee_calculator',
    'add_compute_budget_program',
    'nonce_must_be_writable',
    'spl_token_v3_3_0_release',
    'leave_nonce_on_success',
    'reject_empty_instruction_without_program',
    'fixed_memcpy_nonoverlapping_check',
    'reject_non_rent_exempt_vote_withdraws',
    'evict_invalid_stakes_cache_entries',
    'allow_votes_to_directly_update_vote_state'
    'cap_accounts_data_len',
    'max_tx_account_locks',
    'require_rent_exempt_accounts',
    'filter_votes_outside_slot_hashes',
    'update_syscall_base_costs',
    'stake_deactivate_delinquent_instruction',
    'vote_withdraw_authority_may_change_authorized_voter',
    'spl_associated_token_account_v1_0_4',
    'reject_vote_account_close_unless_zero_credit_epoch',
    'add_get_processed_sibling_instruction_syscall',
    'bank_transaction_count_fix',
    'disable_bpf_deprecated_load_instructions',
    'disable_bpf_unresolved_symbols_at_runtime',
    'record_instruction_in_transaction_context_push',
    'syscall_saturated_math',
    'check_physical_overlapping',
    'limit_secp256k1_recovery_id',
    'disable_deprecated_loader',
    'stake_split_uses_rent_sysvar',
    'add_get_minimum_delegation_instruction_to_stake_program',
    'drop_redundant_turbine_path',
    'executables_incur_cpi_data_cost',
    'fix_recent_blockhashes',
    'update_rewards_from_cached_accounts',
    'spl_token_v3_4_0',
    'spl_associated_token_account_v1_1_0',
    'default_units_per_instruction',
    'stake_allow_zero_undelegated_amount',
    'require_static_program_ids_in_transaction',
    'add_set_compute_unit_price_ix',
    'include_account_index_in_rent_error',
    'add_shred_type_to_shred_seed',
    'warp_timestamp_with_a_vengeance',
    'separate_nonce_from_blockhash',
    'enable_durable_nonce',
    'vote_state_update_credit_per_dequeue',
    'quick_bail_on_panic',
    'nonce_must_be_authorized',
    'nonce_must_be_advanceable',
    'vote_authorize_with_seed',
    'cap_accounts_data_size_per_block',
    'preserve_rent_epoch_for_rent_exempt_accounts',
    'disable_rehash_for_rent_epoch',
    'on_load_preserve_rent_epoch_for_rent_exempt_accounts',
    'prevent_crediting_accounts_that_end_rent_paying',
    'use_default_units_in_fee_calculation',
    'vote_state_update_root_fix',
    'cap_accounts_data_allocations_per_transaction',
    'check_syscall_outputs_do_not_overlap',
    'remove_congestion_multiplier_from_fee_calculation',
    'enable_request_heap_frame_ix',
    'round_up_heap_size',
    'account_hash_ignore_slot',
    'enable_early_verification_of_account_modifications',
    'cap_bpf_program_instruction_accounts',
    'disable_builtin_loader_ownership_chains',
    'limit_max_instruction_trace_length',
    'delay_visibility_of_program_deployment',
    'check_slice_translation_size',
    'move_serialized_len_ptr_in_cpi',
    'enable_program_redeployment_cooldown',
    'libsecp256k1_0_5_upgrade_enabled',
    'dedupe_config_program_signers',
    'system_transfer_zero_check',
    'disable_cpi_setting_executable_and_rent_epoch',
    'require_custodian_for_locked_stake_authorize',
    'vote_stake_checked_instructions',
    'no_overflow_rent_distribution',
    'stake_merge_with_unmatched_credits_observed',
    'remove_deprecated_request_unit_ix',
    'cap_transaction_accounts_data_size',
    'epoch_accounts_hash',
    'checked_arithmetic_in_fee_validation',
    'prevent_rent_paying_rent_recipients',
    'add_set_tx_loaded_accounts_data_size_instruction',
    'native_programs_consume_cu',
    'stop_sibling_instruction_search_at_parent',
    'remove_bpf_loader_incorrect_program_id',
    'stop_truncating_strings_in_syscalls',
    'allow_votes_to_directly_update_vote_state',
    'compact_vote_state_updates'
]

def generate(feature_map_path, header_path, body_path):
    with open(feature_map_path, "r") as json_file:
        feature_map = json.load(json_file)

    header = open(header_path, "w")
    body = open(body_path, "w")

    # Generate struct body of fd_features_t.
    fd_features_t_params = []
    rmap = {}
    fm = feature_map
    for x in fm:
        fd_features_t_params.append(f"    ulong {x['name']};")
        rmap[x["pubkey"]] = x["name"]
    fd_features_t_params = "\n".join(fd_features_t_params)

    # Write header file.
    print(
        f"""/* Code generated by gen_features.py. DO NOT EDIT. */

#ifndef HEADER_fd_src_flamenco_features_fd_features_h
#error "Include fd_features.h instead of this file."
#endif

/* FEATURE_ID_CNT is the number of features in ids */

#define FD_FEATURE_ID_CNT ({len(fm)}UL)

union fd_features {{

  ulong f[ FD_FEATURE_ID_CNT ];

  struct {{
{fd_features_t_params}
  }};

}};""",
        file=header,
    )

    def pubkey_to_c_array(pubkey):
        raw = b58decode(pubkey)
        return '"' + "".join([f"\\x{byte:02x}" for byte in raw]) + '"'

    print(
        f"""/* Code generated by gen_features.py. DO NOT EDIT. */

#include "fd_features.h"
#include <stddef.h>

void
fd_features_enable_all( fd_features_t * f ) {{
  for( fd_feature_id_t const * id = fd_feature_iter_init();
    !fd_feature_iter_done( id );
    id = fd_feature_iter_next( id ) ) {{
    fd_features_set( f, id, 0UL );
  }}
}}

void
fd_features_disable_all( fd_features_t * f ) {{
  for( fd_feature_id_t const * id = fd_feature_iter_init();
    !fd_feature_iter_done( id );
    id = fd_feature_iter_next( id ) ) {{
    fd_features_set( f, id, FD_FEATURE_DISABLED );
  }}
}}

void
fd_features_enable_defaults( fd_features_t * f ) {{
  for( fd_feature_id_t const * id = fd_feature_iter_init();
    !fd_feature_iter_done( id );
    id = fd_feature_iter_next( id ) ) {{
      if ( id->default_activated == 1) {{
        fd_features_set( f, id, 0UL );
      }}
    }}
}}

fd_feature_id_t const ids[] = {{
{
    chr(0xa).join([
    f'''  {{ .index  = offsetof(fd_features_t, {x["name"]})>>3,
    .id     = {{{pubkey_to_c_array(x["pubkey"])}}}
              /* {x["pubkey"]} */ ,
    .default_activated = {1 if x["name"] in REMOVED_FEATURES else 0}
              }},
'''
    for x in fm
    ])
}
  {{ .index = ULONG_MAX }}
}};

/* TODO replace this with fd_map_perfect */

FD_FN_CONST fd_feature_id_t const *
fd_feature_id_query( ulong prefix ) {{

  switch( prefix ) {{
{
    chr(0xa).join([
    f'''  case {"0x%016x" % struct.unpack("<Q", b58decode(x["pubkey"])[:8])}: return &ids[{"% 4d" % (i)} ];'''
    for i, x in enumerate(fm)
    ])
}
  default: break;
  }}

  return NULL;
}}

/* Verify that offset calculations are correct */

{
    chr(0xa).join([
    'FD_STATIC_ASSERT( offsetof( fd_features_t, %-55s )>>3==%3dUL, layout );' % (x["name"], i)
    for i, x in enumerate(fm)
    ])
}

FD_STATIC_ASSERT( sizeof( fd_features_t )>>3==FD_FEATURE_ID_CNT, layout );""",
        file=body,
    )


def main():
    script_dir = Path(__file__).parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--feature_map",
        help="feature map file",
        type=Path,
        default=script_dir / "feature_map.json",
    )
    parser.add_argument(
        "--header",
        help="header file to write",
        type=Path,
        default=script_dir / "fd_features_generated.h",
    )
    parser.add_argument(
        "--body",
        help="body file to write",
        type=Path,
        default=script_dir / "fd_features_generated.c",
    )
    args = parser.parse_args()

    generate(
        feature_map_path=args.feature_map,
        header_path=args.header,
        body_path=args.body,
    )


if __name__ == "__main__":
    main()
