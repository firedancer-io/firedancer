#include "fd_restart.h"
#include "../../util/fd_util.h"
#include "../../flamenco/stakes/fd_stakes.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void *
fd_restart_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_restart_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset( mem, 0, fd_restart_footprint() );
  return mem;
}

fd_restart_t *
fd_restart_join( void * restart ) {
  if( FD_UNLIKELY( !restart ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)restart, fd_restart_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_restart_t * restart_ = (fd_restart_t *)restart;
  return restart_;
}

void
fd_restart_init( fd_restart_t * restart,
                 fd_vote_accounts_t const * accs,
                 fd_tower_t const * tower,
                 fd_slot_history_t const * slot_history,
                 fd_funk_t * funk,
                 fd_blockstore_t * blockstore,
                 fd_pubkey_t * my_pubkey,
                 fd_pubkey_t * coordinator_pubkey,
                 uchar * out_buf,
                 ulong * out_buf_len ) {
  restart->num_vote_accts     = fd_stake_weights_by_node( accs, restart->stake_weights );
  restart->total_stake        = 0;
  restart->total_active_stake = 0;
  restart->tower_root         = tower->root;
  restart->funk_root          = fd_funk_last_publish( funk )->ul[0];
  FD_TEST( restart->num_vote_accts <= MAX_RESTART_PEERS );
  FD_LOG_WARNING(( "fd_restart_init: funk root=%lu, tower root=%lu", restart->funk_root, restart->tower_root ));

  FD_LOG_NOTICE(( "%lu staked voters", restart->num_vote_accts ));
  for( ulong i=0; i<restart->num_vote_accts; i++ ) {
    FD_LOG_NOTICE(( "fd_restart_init: %s holds stake amount=%lu",
                    FD_BASE58_ENC_32_ALLOCA( &restart->stake_weights[i].key ),
                    restart->stake_weights[i].stake ));
    restart->total_stake += restart->stake_weights[i].stake;
  }

  fd_gossip_restart_last_voted_fork_slots_t * msg = (fd_gossip_restart_last_voted_fork_slots_t *) fd_type_pun( out_buf );
  /* FIXME: Need to check whether this tower loaded from the funk checkpoint is the right one to use; It seems stale. */
  if( fd_tower_votes_cnt( tower->votes ) == 0 ) {
    FD_LOG_ERR(( "The tower loaded has 0 votes and wen-restart cannot proceed without an appropriate tower" ));
  }
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
  *out_buf_len = sizeof(fd_gossip_restart_last_voted_fork_slots_t) + ( num_slots+bits_per_uchar )/bits_per_uchar;
  FD_LOG_NOTICE(( "fd_restart_init: encoding %lu bits in bitmap", num_slots ));

  uchar * bitmap = out_buf + sizeof(fd_gossip_restart_last_voted_fork_slots_t);
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

  restart->stage                           = WR_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM;
  restart->heaviest_fork_slot              = 0;
  restart->heaviest_fork_ready             = 0;
  restart->coordinator_heaviest_fork_ready = 0;
  restart->coordinator_heaviest_fork_sent  = 0;
  fd_memcpy( restart->my_pubkey.key, my_pubkey, sizeof(fd_pubkey_t) );
  fd_memcpy( restart->coordinator_pubkey.key, coordinator_pubkey, sizeof(fd_pubkey_t) );
  fd_memset( restart->slot_to_stake, 0, sizeof(restart->slot_to_stake) );
  fd_memset( restart->last_voted_fork_slots_received, 0, sizeof(restart->last_voted_fork_slots_received) );

  FD_LOG_NOTICE(( "Wen-restart coordinator pubkey is %s; My pubkey is %s",
                  FD_BASE58_ENC_32_ALLOCA( &restart->coordinator_pubkey ),
                  FD_BASE58_ENC_32_ALLOCA( &restart->my_pubkey ) ));
}

static void
fd_restart_recv_last_voted_fork_slots( fd_restart_t * restart,
                                       fd_gossip_restart_last_voted_fork_slots_t * msg,
                                       ulong * out_heaviest_fork_found ) {
  if( FD_UNLIKELY( restart->stage!=WR_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM ) ) {
    return;
  }

  ulong stake          = ULONG_MAX;
  fd_pubkey_t * pubkey = &msg->from;
  for( ulong i=0; i<restart->num_vote_accts; i++ ) {
    if( FD_UNLIKELY( memcmp( pubkey->key, restart->stake_weights[i].key.key, sizeof(fd_pubkey_t) )==0 ) ) {
      if( FD_UNLIKELY( restart->last_voted_fork_slots_received[i] ) ) {
        FD_LOG_NOTICE(( "Duplicate last_voted_fork_slots message from %s", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
        return;
      }
      stake = restart->stake_weights[i].stake;
      restart->last_voted_fork_slots_received[i] = 1;
      break;
    }
  }
  if( FD_UNLIKELY( stake==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Get last_voted_fork_slots message from unknown validator: %s", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
    return;
  }

  restart->total_active_stake += stake;
  ulong percentile = restart->total_active_stake * 100 / restart->total_stake;
  FD_LOG_NOTICE(( "Total active stake: %lu/%lu = %lu%\n",
                  restart->total_active_stake,
                  restart->total_stake,
                  percentile));

  if( FD_UNLIKELY( msg->offsets.discriminant==fd_restart_slots_offsets_enum_run_length_encoding ) ) {
    FD_LOG_ERR(( "Decoding RunLengthEncoding offsets is not implemented yet" ));
  }

  for( ulong i=0, last_voted_slot = msg->last_voted_slot; \
       i<msg->offsets.inner.raw_offsets.offsets.len; i++ ) {
    if( FD_UNLIKELY( last_voted_slot<restart->tower_root+i ) ) break;

    ulong slot     = last_voted_slot-i;
    ulong byte_off = i/bits_per_uchar;
    ulong bit_off  = i%bits_per_uchar;
    uchar bit      = msg->offsets.inner.raw_offsets.offsets.bits.bits[ byte_off ] & (uchar)(1<<bit_off);
    if( FD_LIKELY( bit ) ) {
      ulong offset = slot-restart->tower_root;
      restart->slot_to_stake[ offset ] += stake;
    }
  }

  if( FD_UNLIKELY( percentile>=WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT ) ) {
    ulong stake_threshold = restart->total_active_stake
                            - restart->total_stake * HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT / 100UL;

    FD_LOG_NOTICE(( "Stake threshold: %lu", stake_threshold ));
    restart->heaviest_fork_slot = restart->tower_root;
    for( ulong offset=0; offset<LAST_VOTED_FORK_MAX_SLOTS; offset++ ) {
      if( FD_LIKELY( restart->slot_to_stake[ offset ]>=stake_threshold ) ) {
        restart->heaviest_fork_slot = restart->tower_root+offset;
      }
    }
    FD_LOG_NOTICE(( "Found heaviest fork slot=%lu", restart->heaviest_fork_slot ));
    if( FD_UNLIKELY( restart->heaviest_fork_slot < restart->funk_root ) ) {
      FD_LOG_ERR(( "Funk root(%lu) is higher than the heaviest fork slot(%lu)",
                   restart->funk_root, restart->heaviest_fork_slot ));
    }

    *out_heaviest_fork_found = 1;
    restart->stage           = WR_STAGE_FIND_HEAVIEST_FORK_BANK_HASH;
  }
}

static void
fd_restart_recv_heaviest_fork( fd_restart_t * restart,
                               fd_gossip_restart_heaviest_fork_t * msg ) {
  if( FD_LIKELY( memcmp( restart->coordinator_pubkey.key,
                         msg->from.key, sizeof(fd_pubkey_t) )==0 ) ) {
    FD_LOG_WARNING(( "Received a restart_heaviest_fork message: slot=%lu, hash=%s",
                     msg->last_slot, FD_BASE58_ENC_32_ALLOCA( &msg->last_slot_hash ) ));
    restart->coordinator_heaviest_fork_slot = msg->last_slot;
    fd_memcpy( &restart->coordinator_heaviest_fork_bank_hash,
               &msg->last_slot_hash,
               sizeof(fd_hash_t) );
    restart->coordinator_heaviest_fork_ready = 1;
  } else {
    FD_LOG_WARNING(( "Received a restart_heaviest_fork message from non-coordinator %s",
                     FD_BASE58_ENC_32_ALLOCA( &msg->from ) ));
  }
}

void
fd_restart_recv_gossip_msg( fd_restart_t * restart,
                            void * gossip_msg,
                            ulong * out_heaviest_fork_found ) {
    uchar * src = (uchar *) fd_type_pun( gossip_msg );
    uint discriminant = FD_LOAD( uint, src );
    src += sizeof(uint);

    if( discriminant==fd_crds_data_enum_restart_heaviest_fork ) {
      /* Incoming packet from gossip tile. Format:
         Wen-restart gossip message for heaviest_fork (fd_gossip_restart_heaviest_fork_t)
      */
      fd_gossip_restart_heaviest_fork_t * msg = (fd_gossip_restart_heaviest_fork_t * ) fd_type_pun( src );
      fd_restart_recv_heaviest_fork( restart, msg );
    } else if( discriminant==fd_crds_data_enum_restart_last_voted_fork_slots ) {
      /* Incoming packet from gossip tile. Format:
         Wen-restart gossip message for last voted fork slots (fd_gossip_restart_last_voted_fork_slots_t)
         Bitmap in raw format (uchar* - bitmap size is specified in the gossip message)
      */
      fd_gossip_restart_last_voted_fork_slots_t * msg = (fd_gossip_restart_last_voted_fork_slots_t * ) fd_type_pun( src );
      msg->offsets.inner.raw_offsets.offsets.bits.bits = src + sizeof(fd_gossip_restart_last_voted_fork_slots_t);
      fd_restart_recv_last_voted_fork_slots( restart, msg, out_heaviest_fork_found );
    }
}

void
fd_restart_find_heaviest_fork_bank_hash( fd_restart_t * restart,
                                         fd_funk_t * funk,
                                         fd_blockstore_t * blockstore,
                                         ulong * out_need_repair ) {
  fd_blockstore_start_write( blockstore );

  fd_hash_t const * bank_hash = fd_blockstore_bank_hash_query( blockstore, restart->heaviest_fork_slot );
  if( FD_UNLIKELY( bank_hash != NULL ) ) {
    /* No need to repair and replay */
    FD_LOG_NOTICE(( "Found bank hash of slot%lu in blockstore: %s",
                    restart->heaviest_fork_slot,
                    FD_BASE58_ENC_32_ALLOCA( bank_hash )));
    fd_memcpy( &restart->heaviest_fork_bank_hash, bank_hash, sizeof(fd_hash_t) );
    restart->heaviest_fork_ready = 1;

    fd_blockstore_end_write( blockstore );
    *out_need_repair = 0;
    return;
  } else {
    *out_need_repair = 1;
  }

  /* Cancel txns after the funk root from funk */
  fd_funk_start_write( funk );
  for( ulong slot=restart->funk_root+1; slot<=restart->heaviest_fork_slot; slot++ ) {
    fd_hash_t const * block_hash = fd_blockstore_block_hash_query( blockstore, slot );
    if( FD_UNLIKELY( block_hash==NULL ) ) continue;

    fd_funk_txn_xid_t xid;
    memcpy( xid.uc, block_hash, sizeof(fd_funk_txn_xid_t) );
    xid.ul[0]               = slot;
    fd_funk_txn_t * txn_map = fd_funk_txn_map( funk, fd_funk_wksp( funk ) );
    fd_funk_txn_t * txn     = fd_funk_txn_query( &xid, txn_map );
    if( FD_UNLIKELY( txn==NULL ) ) continue;
    FD_TEST( fd_funk_txn_cancel( funk, txn, 1 ) );
  }
  fd_funk_end_write( funk );

  /* Remove slots after the funk root from blockstore */
  fd_block_map_t * block_map = fd_blockstore_block_map( blockstore );
  for( ulong slot=restart->funk_root+1; slot<=restart->heaviest_fork_slot; slot++ ){
    fd_block_map_t * block_map_entry = fd_block_map_query( block_map, &slot, NULL );
    if( block_map_entry != NULL ){
      fd_blockstore_slot_remove( blockstore, slot);
      FD_LOG_NOTICE(( "Cleaning up slot%lu from blockstore for wen-restart repair", slot ));
    }
  }

  fd_blockstore_end_write( blockstore );
}

void
fd_restart_verify_heaviest_fork( fd_restart_t * restart,
                                 uchar * out_buf,
                                 ulong * out_send ) {
  if( FD_UNLIKELY(( restart->heaviest_fork_ready==1 )) ) {
    if( FD_UNLIKELY( memcmp( restart->my_pubkey.key,
                             restart->coordinator_pubkey.key,
                             sizeof(fd_pubkey_t) )==0 ) ) {
      // I am the wen-restart coordinator
      if( FD_UNLIKELY( !restart->coordinator_heaviest_fork_sent ) ) {
        restart->coordinator_heaviest_fork_sent = 1;
        fd_gossip_restart_heaviest_fork_t * msg = (fd_gossip_restart_heaviest_fork_t *) fd_type_pun( out_buf );
        msg->observed_stake = 0;
        msg->last_slot      = restart->heaviest_fork_slot;
        fd_memcpy( msg->last_slot_hash.hash, restart->heaviest_fork_bank_hash.hash, sizeof(fd_hash_t) );
        *out_send = 1;
      }
    } else if( FD_UNLIKELY( restart->coordinator_heaviest_fork_ready==1 ) ) {
      // I am not the wen-restart coordinator
      if( restart->heaviest_fork_slot!=restart->coordinator_heaviest_fork_slot ) {
        FD_LOG_ERR(( "Heaviest fork mismatch: my slot=%lu, coordinator slot=%lu",
                     restart->heaviest_fork_slot, restart->coordinator_heaviest_fork_slot ));
      }
      if( memcmp( restart->heaviest_fork_bank_hash.hash,
                  restart->coordinator_heaviest_fork_bank_hash.hash,
                  sizeof(fd_hash_t) )!=0 ) {
        FD_LOG_ERR(( "Heaviest fork mismatch for slot%lu: my hash=%s, coordinator hash=%s",
                     restart->heaviest_fork_slot,
                     FD_BASE58_ENC_32_ALLOCA( &restart->heaviest_fork_bank_hash ),
                     FD_BASE58_ENC_32_ALLOCA( &restart->coordinator_heaviest_fork_bank_hash ) ));
      }
      /* TODO: generate an incremental snapshot */
      restart->stage = WR_STAGE_GENERATE_SNAPSHOT;
      FD_LOG_ERR(( "Wen-restart succeeds with slot=%lu, bank hash=%s",
                   restart->heaviest_fork_slot, FD_BASE58_ENC_32_ALLOCA( &restart->heaviest_fork_bank_hash ) ));
    }
  }
}
