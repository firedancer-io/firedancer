#include "fd_restart.h"
#include "../../util/fd_util.h"
#include "../../flamenco/stakes/fd_stakes.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void
fd_restart_init( fd_restart_state_t * restart_state,
                 fd_vote_accounts_t const * accs,
                 fd_tower_t const * tower,
                 fd_slot_history_t const * slot_history,
                 fd_blockstore_t * blockstore,
                 uchar * buf_out,
                 ulong * buf_len_out ) {
  restart_state->num_vote_accts     = fd_stake_weights_by_node( accs, restart_state->stake_weights );
  restart_state->total_stake        = 0;
  restart_state->total_active_stake = 0;
  restart_state->root               = tower->root;
  FD_TEST( restart_state->num_vote_accts <= MAX_RESTART_PEERS );

  for( ulong i=0; i<restart_state->num_vote_accts; i++ ) {
    FD_LOG_NOTICE(( "fd_restart_init: %s holds stake amount=%lu",
                    FD_BASE58_ENC_32_ALLOCA( &restart_state->stake_weights[i].key ),
                    restart_state->stake_weights[i].stake ));
    restart_state->total_stake += restart_state->stake_weights[i].stake;
  }

  fd_gossip_restart_last_voted_fork_slots_t * msg = (fd_gossip_restart_last_voted_fork_slots_t *) fd_type_pun( buf_out );
  /* FIXME: Need to check whether this tower loaded from the funk checkpoint is the right one to use; It seems stale. */
  msg->last_voted_slot = fd_tower_votes_peek_tail_const( tower->votes )->slot;
  if( FD_UNLIKELY( msg->last_voted_slot>=slot_history->next_slot ) ) {
    FD_LOG_ERR(( "Voted slot should not exceed the end of slot history" ));
  }

  fd_blockstore_start_read( blockstore );
  fd_hash_t const * vote_block_hash = fd_blockstore_block_hash_query( blockstore, msg->last_voted_slot );
  fd_blockstore_end_read( blockstore );
  if( FD_UNLIKELY( vote_block_hash==NULL ) ) {
    FD_LOG_ERR(( "fd_restart_init: cannot query the block hash of last voted slot=%lu from blockstore", msg->last_voted_slot ));
  } else {
    FD_LOG_NOTICE(( "fd_restart_init: voted for slot%lu with block hash %s", msg->last_voted_slot, FD_BASE58_ENC_32_ALLOCA( vote_block_hash ) ));
    fd_memcpy( msg->last_voted_hash.hash, vote_block_hash->hash, sizeof(fd_hash_t) );
  }

  ulong end_slot   = msg->last_voted_slot;
  ulong start_slot = ( end_slot>LAST_VOTED_FORK_MAX_SLOTS? end_slot-LAST_VOTED_FORK_MAX_SLOTS : 0 );
  ulong num_slots  = end_slot-start_slot+1;
  msg->offsets.discriminant                            = fd_restart_slots_offsets_enum_raw_offsets;
  msg->offsets.inner.raw_offsets.offsets.has_bits      = 1;
  msg->offsets.inner.raw_offsets.offsets.len           = num_slots;
  msg->offsets.inner.raw_offsets.offsets.bits.bits_len = ( num_slots+bits_per_uchar )/bits_per_uchar;
  *buf_len_out = sizeof(fd_gossip_restart_last_voted_fork_slots_t) + ( num_slots+bits_per_uchar )/bits_per_uchar;
  FD_LOG_NOTICE(( "fd_restart_init: encoding %lu bits in bitmap", num_slots ));

  uchar * bitmap = buf_out + sizeof(fd_gossip_restart_last_voted_fork_slots_t);
  for( ulong i=start_slot; i<=end_slot; i++ ) {
    ulong in_idx          = ( i/bits_per_ulong )%( slot_history->bits.bits->blocks_len );
    ulong in_bit_off      = i%bits_per_ulong;

    ulong offset_from_end = end_slot-i;
    ulong out_idx         = offset_from_end/bits_per_uchar;
    int out_bit_off       = offset_from_end%bits_per_uchar;

    if( FD_LIKELY( slot_history->bits.bits->blocks[ in_idx ] & (1UL<<in_bit_off) ) ) {
      /* bit#i is 1 in slot_history */
      bitmap[ out_idx ] = fd_uchar_set_bit( bitmap[ out_idx ], out_bit_off );
    } else {
      /* bit#i is 0 in slot_history */
      bitmap[ out_idx ] = fd_uchar_clear_bit( bitmap[ out_idx ], out_bit_off );
    }
  }

  restart_state->stage = WR_STATE_FIND_HEAVIEST_FORK;
  restart_state->heaviest_fork_slot = ULONG_MAX;
  fd_memset( restart_state->slot_to_stake, 0, sizeof(restart_state->slot_to_stake) );
  fd_memset( restart_state->last_voted_fork_slots_received, 0, sizeof(restart_state->last_voted_fork_slots_received) );
}

void
fd_restart_recv_last_voted_fork_slots( fd_restart_state_t * restart_state,
                                       fd_gossip_restart_last_voted_fork_slots_t * msg,
                                       ulong * out_restart_slot ) {
  if( FD_UNLIKELY( restart_state->stage!=WR_STATE_FIND_HEAVIEST_FORK ) ) {
    return;
  }

  ulong stake          = ULONG_MAX;
  fd_pubkey_t * pubkey = &msg->from;
  for( ulong i=0; i<restart_state->num_vote_accts; i++ ) {
    if( FD_UNLIKELY( memcmp( pubkey->key, restart_state->stake_weights[i].key.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      if( FD_UNLIKELY( restart_state->last_voted_fork_slots_received[i] ) ) {
        FD_LOG_NOTICE(( "Duplicate last_voted_fork_slots message from %s", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
        return;
      }
      stake = restart_state->stake_weights[i].stake;
      restart_state->last_voted_fork_slots_received[i] = 1;
      break;
    }
  }
  if( FD_UNLIKELY( stake==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Get last_voted_fork_slots message from unknown validator: %s", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
    return;
  }

  restart_state->total_active_stake += stake;
  ulong percentile = restart_state->total_active_stake * 100 / restart_state->total_stake;
  FD_LOG_NOTICE(( "Total active stake: %lu/%lu = %lu%\n",
                  restart_state->total_active_stake,
                  restart_state->total_stake,
                  percentile));

  if( FD_UNLIKELY( msg->offsets.discriminant==fd_restart_slots_offsets_enum_run_length_encoding ) ) {
    FD_LOG_ERR(( "Decoding RunLengthEncoding offsets is not implemented yet" ));
  }

  for( ulong i=0, last_voted_slot = msg->last_voted_slot; \
       i<msg->offsets.inner.raw_offsets.offsets.len; i++ ) {
    if( FD_UNLIKELY( last_voted_slot<restart_state->root+i ) ) break;

    ulong slot     = last_voted_slot-i;
    ulong byte_off = i/bits_per_uchar;
    ulong bit_off  = i%bits_per_uchar;
    uchar bit      = msg->offsets.inner.raw_offsets.offsets.bits.bits[ byte_off ] & (uchar)(1<<bit_off);
    if( FD_LIKELY( bit ) ) {
      ulong offset = slot-restart_state->root;
      restart_state->slot_to_stake[ offset ] += stake;
    }
  }

  if( FD_UNLIKELY( percentile>=WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT ) ) {
    ulong stake_threshold = restart_state->total_active_stake
                            - restart_state->total_stake * HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT / 100UL;

    FD_LOG_NOTICE(( "Stake threshold: %lu", stake_threshold ));
    restart_state->heaviest_fork_slot = restart_state->root;
    for( ulong offset=0; offset<LAST_VOTED_FORK_MAX_SLOTS; offset++ ) {
      if( FD_LIKELY( restart_state->slot_to_stake[ offset ]>=stake_threshold ) ) {
        restart_state->heaviest_fork_slot = restart_state->root+offset;
      }
    }
    FD_LOG_NOTICE(( "Found heaviest fork slot=%lu", restart_state->heaviest_fork_slot ));

    /* Notify the store tile for repairing slots from root to restart_state->heaviest_fork_slot */
    *out_restart_slot = restart_state->heaviest_fork_slot;
    FD_LOG_WARNING(( "Reparing and replaying slots before %lu, not implemented yet", restart_state->heaviest_fork_slot ));

    restart_state->stage = WR_STATE_AGREE_ON_HEAVIEST_FORK;
  }
}
