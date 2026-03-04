#include "fd_solfuzz_private.h"
#include "generated/context.pb.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../../features/fd_features.h"
#include "../../accdb/fd_accdb_sync.h"
#include <assert.h>

void
fd_solfuzz_pb_restore_fee_rate_governor( fd_bank_t *                              bank,
                                         fd_exec_test_fee_rate_governor_t const * fee_rate_governor ) {
  fd_fee_rate_governor_t * frg = fd_bank_fee_rate_governor_modify( bank );
  *frg = (fd_fee_rate_governor_t){
    .target_lamports_per_signature = fee_rate_governor->target_lamports_per_signature,
    .target_signatures_per_slot    = fee_rate_governor->target_signatures_per_slot,
    .min_lamports_per_signature    = fee_rate_governor->min_lamports_per_signature,
    .max_lamports_per_signature    = fee_rate_governor->max_lamports_per_signature,
    .burn_percent                  = (uchar)fee_rate_governor->burn_percent,
  };
}

void
fd_solfuzz_pb_restore_epoch_schedule( fd_bank_t *                           bank,
                                      fd_exec_test_epoch_schedule_t const * epoch_schedule ) {
  fd_epoch_schedule_t * es = fd_bank_epoch_schedule_modify( bank );
  *es = (fd_epoch_schedule_t){
    .slots_per_epoch             = epoch_schedule->slots_per_epoch,
    .leader_schedule_slot_offset = epoch_schedule->leader_schedule_slot_offset,
    .warmup                      = epoch_schedule->warmup,
    .first_normal_epoch          = epoch_schedule->first_normal_epoch,
    .first_normal_slot           = epoch_schedule->first_normal_slot,
  };
}

void
fd_solfuzz_pb_restore_rent( fd_bank_t *                 bank,
                            fd_exec_test_rent_t const * rent ) {
  fd_rent_t * r = fd_bank_rent_modify( bank );
  *r = (fd_rent_t){
    .lamports_per_uint8_year = rent->lamports_per_byte_year,
    .exemption_threshold     = rent->exemption_threshold,
    .burn_percent            = (uchar)rent->burn_percent,
  };
}

void
fd_solfuzz_pb_restore_blockhash_queue( fd_bank_t *                                    bank,
                                       fd_exec_test_blockhash_queue_entry_t const *   entries,
                                       ulong                                          entries_cnt ) {
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( fd_bank_block_hash_queue_modify( bank ), blockhash_seed );
  for( ulong i=0UL; i<entries_cnt; i++ ) {
    fd_hash_t hash                   = FD_LOAD( fd_hash_t, entries[i].blockhash );
    ulong     lamports_per_signature = entries[i].lamports_per_signature;

    fd_blockhash_info_t * blockhash = fd_blockhashes_push_new( blockhashes, &hash );
    blockhash->fee_calculator = (fd_fee_calculator_t){
      .lamports_per_signature = lamports_per_signature
    };
  }
}

ulong
fd_solfuzz_pb_get_slot( fd_exec_test_acct_state_t const * acct_states,
                        ulong                             acct_states_cnt ) {
  for( ulong i=0UL; i<acct_states_cnt; i++ ) {
    if( !memcmp( &acct_states[i].address, &fd_sysvar_clock_id, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( acct_states[i].data->size==sizeof(fd_sol_sysvar_clock_t) );
      return FD_LOAD( ulong, acct_states[i].data->bytes );
    }
  }
  FD_LOG_ERR(( "invariant violation: clock sysvar account not found in acct states" ));
}

int
fd_solfuzz_pb_load_account( fd_runtime_t *                    runtime,
                            fd_accdb_user_t *                 accdb,
                            fd_funk_txn_xid_t const *         xid,
                            fd_exec_test_acct_state_t const * state,
                            ulong                             acc_idx ) {
  if( state->lamports==0UL ) return 0;

  ulong size = 0UL;
  if( state->data ) size = state->data->size;

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  /* Account must not yet exist */
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( fd_accdb_open_ro( accdb, ro, xid, pubkey ) ) ) {
    fd_accdb_close_ro( accdb, ro );
    return 0;
  }

  fd_accdb_rw_t rw[1];
  fd_accdb_open_rw( accdb, rw, xid, pubkey, size, FD_ACCDB_FLAG_CREATE );
  if( state->data ) {
    fd_accdb_ref_data_set( accdb, rw, state->data->bytes, size );
  }
  runtime->accounts.starting_lamports[ acc_idx ] = state->lamports;
  runtime->accounts.starting_dlen    [ acc_idx ] = size;
  fd_accdb_ref_lamports_set( rw, state->lamports   );
  fd_accdb_ref_exec_bit_set( rw, state->executable );
  fd_accdb_ref_owner_set   ( rw, state->owner      );
  fd_accdb_close_rw( accdb, rw );

  return 1;
}

int
fd_solfuzz_pb_restore_features( fd_features_t *                    features,
                                fd_exec_test_feature_set_t const * feature_set ) {
  fd_features_disable_all( features );
  for( ulong j=0UL; j < feature_set->features_count; j++ ) {
    ulong                   prefix = feature_set->features[j];
    fd_feature_id_t const * id     = fd_feature_id_query( prefix );
    if( FD_UNLIKELY( !id ) ) {
      FD_LOG_WARNING(( "unsupported feature ID 0x%016lx", prefix ));
      return 0;
    }
    /* Enabled since genesis */
    fd_features_set( features, id, 0UL );
  }
  return 1;
}

#if FD_HAS_FLATCC

void
fd_solfuzz_fb_restore_features( fd_features_t *                    features,
                                SOL_COMPAT_NS(FeatureSet_table_t)  feature_set ) {
  if( FD_UNLIKELY( !feature_set ) ) return;

  fd_features_disable_all( features );
  flatbuffers_uint64_vec_t input_features     = SOL_COMPAT_NS(FeatureSet_features( feature_set ));
  ulong                    input_features_cnt = flatbuffers_uint64_vec_len( input_features );
  for( ulong i=0UL; i<input_features_cnt; i++ ) {
    ulong                   prefix = flatbuffers_uint64_vec_at( input_features, i );
    fd_feature_id_t const * id     = fd_feature_id_query( prefix );
    if( FD_UNLIKELY( !id ) ) {
      FD_LOG_ERR(( "unsupported feature ID 0x%016lx", prefix ));
    }
    /* Enabled since genesis */
    fd_features_set( features, id, 0UL );
  }
}

#endif /* FD_HAS_FLATCC */
