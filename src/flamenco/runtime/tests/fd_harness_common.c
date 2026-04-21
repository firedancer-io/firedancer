#include "fd_solfuzz_private.h"
#include "generated/context.pb.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../../features/fd_features.h"
#include <assert.h>

void
fd_solfuzz_pb_restore_fee_rate_governor( fd_bank_t *                              bank,
                                         fd_exec_test_fee_rate_governor_t const * fee_rate_governor ) {
  fd_fee_rate_governor_t * frg = &bank->f.fee_rate_governor;
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
  fd_epoch_schedule_t * es = &bank->f.epoch_schedule;
  *es = (fd_epoch_schedule_t){
    .slots_per_epoch             = epoch_schedule->slots_per_epoch,
    .leader_schedule_slot_offset = epoch_schedule->leader_schedule_slot_offset,
    .warmup                      = epoch_schedule->warmup,
    .first_normal_epoch          = epoch_schedule->first_normal_epoch,
    .first_normal_slot           = epoch_schedule->first_normal_slot,
  };
}

void
fd_solfuzz_pb_restore_blockhash_queue( fd_bank_t *                                    bank,
                                       fd_exec_test_blockhash_queue_entry_t const *   entries,
                                       ulong                                          entries_cnt ) {
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( &bank->f.block_hash_queue, blockhash_seed );
  for( ulong i=0UL; i<entries_cnt; i++ ) {
    fd_hash_t hash                   = FD_LOAD( fd_hash_t, entries[i].blockhash );
    ulong     lamports_per_signature = entries[i].lamports_per_signature;

    fd_blockhash_info_t * blockhash = fd_blockhashes_push_new( blockhashes, &hash );
    blockhash->lamports_per_signature = lamports_per_signature;
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
                            fd_accdb_t *                      accdb,
                            fd_accdb_fork_id_t                fork_id,
                            fd_exec_test_acct_state_t const * state,
                            ulong                             acc_idx ) {
  (void)runtime; (void)acc_idx;
  if( state->lamports==0UL ) return 0;

  ulong size = 0UL;
  if( state->data ) size = state->data->size;

  fd_pubkey_t pubkey[1];  memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

  /* Account must not yet exist */
  if( FD_UNLIKELY( fd_accdb_exists( accdb, fork_id, pubkey->key ) ) ) {
    return 0;
  }

  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, fork_id, pubkey->key, 1, 1 );
  if( state->data && size ) {
    fd_memcpy( entry.data, state->data->bytes, size );
  }
  entry.data_len   = size;
  entry.lamports   = state->lamports;
  entry.executable = state->executable;
  fd_memcpy( entry.owner, state->owner, 32UL );
  entry.commit = 1;
  fd_accdb_unwrite_one( accdb, &entry );

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
