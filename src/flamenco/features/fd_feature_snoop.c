#include "fd_feature_snoop.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"

void
fd_feature_snoop_account( fd_feature_snoop_t * snoop,
                          fd_pubkey_t const *  pubkey,
                          ulong                lamports,
                          uchar const *        owner,
                          uchar const *        data,
                          ulong                data_len ) {
  if( FD_LIKELY( !lamports ) ) return;

  /* Only feature-program-owned accounts carry feature activation state.
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L42-L44 */
  if( FD_LIKELY( memcmp( owner, fd_solana_feature_program_id.uc, 32UL ) ) ) return;

  /* Resolve the account address to a known feature id (by 8-byte prefix,
     then confirm the full pubkey). */
  fd_feature_id_t const * id = fd_feature_id_query( fd_ulong_load_8( pubkey->uc ) );
  if( FD_UNLIKELY( !id || !fd_pubkey_eq( pubkey, &id->id ) ) ) return;

  /* Account data size must be >= FD_FEATURE_SIZEOF (9 bytes).
     https://github.com/anza-xyz/solana-sdk/blob/6512aca61167088ce10f2b545c35c9bcb1400e70/feature-gate-interface/src/lib.rs#L45-L47 */
  fd_feature_t feature[1];
  if( FD_UNLIKELY( data_len<sizeof(fd_feature_t) || !fd_feature_decode( feature, data, data_len ) ) ) return;

  snoop->present        [ id->index ] = 1;
  snoop->is_active      [ id->index ] = feature->is_active;
  snoop->activation_slot[ id->index ] = feature->activation_slot;
}

void
fd_feature_snoop_finalize( fd_features_t *             features,
                           ulong                       slot,
                           fd_epoch_schedule_t const * epoch_schedule,
                           fd_feature_snoop_t const *  snoop ) {

  /* Mirror fd_feature_restore (per id), reading the snooped account state
     instead of the accounts database. */
  int at_epoch_boundary = fd_slot_to_epoch( epoch_schedule, slot, NULL )!=fd_slot_to_epoch( epoch_schedule, slot+1UL, NULL );

  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    if( FD_UNLIKELY( id->cleaned_up ) ) { fd_features_set( features, id, 0UL ); continue; }

    fd_features_set( features, id, FD_FEATURE_DISABLED );

    /* Skip reverted features */
    if( FD_UNLIKELY( id->reverted ) ) continue;

    /* No feature account observed in the load stream: stays disabled. */
    if( !snoop->present[ id->index ] ) continue;

    if( snoop->is_active[ id->index ] ) {
      fd_features_set( features, id, snoop->activation_slot[ id->index ] );
    } else if( at_epoch_boundary ) {
      /* Pending feature at the last slot before an epoch boundary:
         pre-populate activation at slot+1. */
      fd_features_set( features, id, slot+1UL );
    }
  }
}
