#include "fd_restart.h"
#include "../../util/fd_util.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

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

static int
fd_restart_recv_enough_stake( fd_restart_t * restart ) {
  ulong received[RESTART_EPOCHS_MAX] = { restart->total_stake_received[0]*100/restart->total_stake[0],
                                         restart->total_stake_received[1]*100/restart->total_stake[1] };
  ulong voted[RESTART_EPOCHS_MAX]    = { restart->total_stake_received_and_voted[0]*100/restart->total_stake[0],
                                         restart->total_stake_received_and_voted[1]*100/restart->total_stake[1] };

  for( ulong e=0; e<RESTART_EPOCHS_MAX; e++ ) {
    FD_LOG_NOTICE(( "Stake received for epoch%lu: %lu/%lu = %lu%\n",
                    restart->root_epoch+e,
                    restart->total_stake_received[e],
                    restart->total_stake[e],
                    received[e] ));
    FD_LOG_NOTICE(( "Stake voted for epoch%lu: %lu/%lu = %lu%\n",
                    restart->root_epoch+e,
                    restart->total_stake_received_and_voted[e],
                    restart->total_stake[e],
                    voted[e] ));
  }

  ulong min_active_stake = received[0];
  if( FD_UNLIKELY( restart->total_stake_received_and_voted[1]*100/restart->total_stake[1]
                   >= WAIT_FOR_NEXT_EPOCH_THRESHOLD_PERCENT ) ) {
    min_active_stake = fd_ulong_min( min_active_stake, received[1] );
  }

  return min_active_stake >= WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT;
}

static void
fd_restart_recv_last_voted_fork_slots( fd_restart_t * restart,
                                       fd_gossip_restart_last_voted_fork_slots_t * msg,
                                       ulong * out_heaviest_fork_found ) {
  if( FD_UNLIKELY( restart->stage!=WR_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM ) ) return;

  /* Check that the last voted slot is either in root_epoch or in root_epoch+1 */
  ulong slot_idx;
  ulong voted_epoch = fd_slot_to_epoch( restart->epoch_schedule, msg->last_voted_slot, &slot_idx );
  if( FD_UNLIKELY( voted_epoch!=restart->root_epoch && voted_epoch!=restart->root_epoch+1 ) ) {
    FD_LOG_WARNING(( "Ignore last_voted_fork_slots message for epoch%lu (root_epoch=%lu, RESTART_EPOCHS_MAX=%lu) from validator %s",
                     voted_epoch, restart->root_epoch, RESTART_EPOCHS_MAX,
                     FD_BASE58_ENC_32_ALLOCA( &msg->from ) ));
    return;
  }
  /* Check that local funk root is not too old for aggregating this message */
  if( FD_UNLIKELY( msg->last_voted_slot>=restart->funk_root+LAST_VOTED_FORK_MAX_SLOTS ) ) {
    FD_LOG_WARNING(( "Ignore last_voted_fork_slots message for slot=%lu (because funk_root=%lu is too old) from validator %s",
                     msg->last_voted_slot, restart->funk_root, FD_BASE58_ENC_32_ALLOCA( &msg->from ) ));
    return;
  }

  /* Find the message sender from restart->stake_weights */
  fd_pubkey_t * pubkey = &msg->from;
  ulong stake_received[ RESTART_EPOCHS_MAX ] = {0UL, 0UL};

  for( ulong e=0; e<RESTART_EPOCHS_MAX; e++ ) {
    for( ulong i=0; i<restart->num_vote_accts[e]; i++ ) {
      if( FD_UNLIKELY( memcmp( pubkey->key, restart->stake_weights[e][i].key.key, sizeof(fd_pubkey_t) )==0 ) ) {
        if( FD_UNLIKELY( restart->last_voted_fork_slots_received[e][i] ) ) {
          FD_LOG_NOTICE(( "Duplicate last_voted_fork_slots message from %s", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
          return;
        }
        stake_received[e] = restart->stake_weights[e][i].stake;
        restart->last_voted_fork_slots_received[e][i] = 1;
        break;
      }
    }
    restart->total_stake_received[e]             += stake_received[e];
    if( FD_LIKELY( restart->root_epoch+e<=voted_epoch ) ) {
      restart->total_stake_received_and_voted[e] += stake_received[e];
    }
  }

  if( FD_UNLIKELY( stake_received[0]==0 && stake_received[1]==0 ) ) {
    FD_LOG_WARNING(( "Get last_voted_fork_slots message from validator with 0 stake: %s", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
    return;
  }

  /* Decode the bitmap in the gossip message, and aggregate stake into slot_to_stake accordingly */
  /* The gossip tile should have already converted the bitmap to raw format before sending the message to the replay tile */
  for( ulong i=0, last_voted_slot = msg->last_voted_slot; \
       i<msg->offsets.inner.raw_offsets.offsets.len; i++ ) {
    if( FD_UNLIKELY( last_voted_slot<restart->funk_root+i ) ) break;

    ulong slot     = last_voted_slot-i;
    ulong byte_off = i/BITS_PER_UCHAR;
    ulong bit_off  = i%BITS_PER_UCHAR;
    uchar bit      = msg->offsets.inner.raw_offsets.offsets.bits.bits[byte_off] & (uchar)(1<<bit_off);
    if( FD_LIKELY( bit ) ) {
      ulong offset = slot-restart->funk_root;
      ulong slot_epoch = fd_slot_to_epoch( restart->epoch_schedule, slot, &slot_idx );
      FD_TEST( slot_epoch==restart->root_epoch || slot_epoch==restart->root_epoch+1 );
      restart->slot_to_stake[offset] += stake_received[slot_epoch-restart->root_epoch];
    }
  }

  if( FD_UNLIKELY( fd_restart_recv_enough_stake( restart ) ) ) {
    ulong stake_threshold[ RESTART_EPOCHS_MAX ] = { restart->total_stake_received[0]
                                                    - restart->total_stake[0]*HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT/100UL,
                                                    restart->total_stake_received[1]
                                                    - restart->total_stake[1]*HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT/100UL };

    restart->heaviest_fork_slot = restart->funk_root;
    for( ulong offset=0; offset<LAST_VOTED_FORK_MAX_SLOTS; offset++ ) {
      ulong slot = restart->funk_root+offset;
      ulong slot_epoch = fd_slot_to_epoch( restart->epoch_schedule, slot, &slot_idx );
      if( slot_epoch!=restart->root_epoch && slot_epoch!=restart->root_epoch+1 ) break;
      if( FD_LIKELY( restart->slot_to_stake[offset]>=stake_threshold[slot_epoch-restart->root_epoch] ) ) {
        restart->heaviest_fork_slot = restart->funk_root+offset;
      }
    }
    FD_LOG_NOTICE(( "Found heaviest fork slot=%lu", restart->heaviest_fork_slot ));

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
    FD_LOG_WARNING(( "Received and ignored a restart_heaviest_fork message from non-coordinator %s",
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
                                         ulong * out_need_repair ) {
  if( FD_UNLIKELY( restart->heaviest_fork_slot<restart->funk_root ) ) {
    FD_LOG_ERR(( "Halting wen-restart because heaviest_fork_slot(%lu) < funk_root(%lu)",
                 restart->heaviest_fork_slot, restart->funk_root ));
  } else if( FD_UNLIKELY( restart->heaviest_fork_slot==restart->funk_root ) ) {
    FD_LOG_NOTICE(( "Found bank hash of slot%lu in funk: %s",
                    restart->funk_root,
                    FD_BASE58_ENC_32_ALLOCA( &restart->root_bank_hash ) ));
    fd_memcpy( &restart->heaviest_fork_bank_hash, &restart->root_bank_hash, sizeof(fd_hash_t) );
    restart->heaviest_fork_ready = 1;

    /* No need to repair and replay */
    *out_need_repair = 0;
  } else {
    /* TODO: ideally, if the heaviest fork slot is in range [funk_root+1, my_last_voted_slot], we can directly
     * get the bank hash from funk instead of doing any repair and replay. */

    /* Cancel any leftover in-preparation transactions from funk */
    fd_funk_start_write( funk );
    fd_funk_txn_cancel_all( funk, 1 );
    fd_funk_end_write( funk );

    /* Need to repair and replay for the bank hash of heaviest_fork_slot */
    *out_need_repair = 1;
  }
}

void
fd_restart_verify_heaviest_fork( fd_restart_t * restart,
                                 uchar * out_buf,
                                 ulong * out_send ) {
  *out_send = 0;
  if( FD_UNLIKELY( restart->stage!=WR_STAGE_FIND_HEAVIEST_FORK_BANK_HASH ) ) return;

  if( FD_UNLIKELY(( restart->heaviest_fork_ready==1 )) ) {
    if( FD_UNLIKELY( memcmp( restart->my_pubkey.key,
                             restart->coordinator_pubkey.key,
                             sizeof(fd_pubkey_t) )==0 ) ) {
      /* I am the wen-restart coordinator */
      fd_gossip_restart_heaviest_fork_t * msg = (fd_gossip_restart_heaviest_fork_t *) fd_type_pun( out_buf );
      msg->observed_stake = 0;
      msg->last_slot      = restart->heaviest_fork_slot;
      fd_memcpy( msg->last_slot_hash.hash, restart->heaviest_fork_bank_hash.hash, sizeof(fd_hash_t) );

      restart->stage = WR_STAGE_GENERATE_SNAPSHOT;
      /* TODO: insert a hard fork and generate an incremental snapshot */
      FD_LOG_WARNING(( "Wen-restart succeeds with slot=%lu, bank hash=%s",
                       restart->heaviest_fork_slot, FD_BASE58_ENC_32_ALLOCA( &restart->heaviest_fork_bank_hash ) ));
      *out_send = 1;
    } else if( FD_UNLIKELY( restart->coordinator_heaviest_fork_ready==1 ) ) {
      /* I am not the wen-restart coordinator */
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

      restart->stage = WR_STAGE_GENERATE_SNAPSHOT;
      /* TODO: insert a hard fork and generate an incremental snapshot */
      FD_LOG_ERR(( "Wen-restart succeeds with slot=%lu, bank hash=%s",
                   restart->heaviest_fork_slot, FD_BASE58_ENC_32_ALLOCA( &restart->heaviest_fork_bank_hash ) ));
      *out_send = 1;
    }
  }
}

void
fd_restart_convert_runlength_to_raw_bitmap( fd_gossip_restart_last_voted_fork_slots_t * msg,
                                            uchar * out_bitmap,
                                            ulong * out_bitmap_len ) {
  ulong bit_cnt   = 0;
  *out_bitmap_len = 0;
  fd_memset( out_bitmap, 0, LAST_VOTED_FORK_RAW_BITMAP_BYTES_MAX );

  for ( ulong i=0, bit=1; i<msg->offsets.inner.run_length_encoding.offsets_len; i++ ) {
    ushort cnt = msg->offsets.inner.run_length_encoding.offsets[i].bits;
    if( bit ) {
      for ( ulong pos=bit_cnt; pos<bit_cnt+cnt; pos++ ) {
        if( FD_UNLIKELY( pos/BITS_PER_UCHAR>=LAST_VOTED_FORK_RAW_BITMAP_BYTES_MAX ) ) {
          *out_bitmap_len = LAST_VOTED_FORK_RAW_BITMAP_BYTES_MAX+1;
          return;
        }
        out_bitmap[pos/BITS_PER_UCHAR] = fd_uchar_set_bit( out_bitmap[pos/BITS_PER_UCHAR], pos%BITS_PER_UCHAR );
      }
    }
    bit_cnt        += cnt;
    *out_bitmap_len = (bit_cnt-1)/BITS_PER_UCHAR+1;
    bit            ^= 1;
  }
  msg->offsets.discriminant                            = fd_restart_slots_offsets_enum_raw_offsets;
  msg->offsets.inner.raw_offsets.offsets.has_bits      = 1;
  msg->offsets.inner.raw_offsets.offsets.len           = bit_cnt;
  msg->offsets.inner.raw_offsets.offsets.bits.bits_len = *out_bitmap_len;
}

void
fd_restart_convert_raw_bitmap_to_runlength( fd_gossip_restart_last_voted_fork_slots_t * msg,
                                            fd_restart_run_length_encoding_inner_t * out_encoding ) {
  ushort cnt=0;
  int    last_bit=1;
  ulong  offsets_len=0;
  for( ulong raw_bitmap_iter=0;
       raw_bitmap_iter<msg->offsets.inner.raw_offsets.offsets.len &&
       offsets_len<LAST_VOTED_FORK_PACKET_BITMAP_BYTES_MAX/sizeof(ushort);
       raw_bitmap_iter++ ) {
    ulong idx  = raw_bitmap_iter/BITS_PER_UCHAR;
    int   off  = raw_bitmap_iter%BITS_PER_UCHAR;
    int   bit = fd_uchar_extract_bit( msg->offsets.inner.raw_offsets.offsets.bits.bits[idx], off );
    if( FD_LIKELY( bit==last_bit ) ) {
      cnt++;
    } else {
      out_encoding[offsets_len++].bits = cnt;
      cnt = 1;
      last_bit = bit;
    }
  }
  out_encoding[offsets_len++].bits = cnt;

  msg->offsets.discriminant                          = fd_restart_slots_offsets_enum_run_length_encoding;
  msg->offsets.inner.run_length_encoding.offsets_len = offsets_len;
  msg->offsets.inner.run_length_encoding.offsets     = out_encoding;
}

void
fd_restart_init( fd_restart_t * restart,
                 ulong funk_root,
                 fd_hash_t * root_bank_hash,
                 fd_vote_accounts_t const ** epoch_stakes,
                 fd_epoch_schedule_t * epoch_schedule,
                 int tower_checkpt_fileno,
                 fd_slot_history_t const * slot_history,
                 fd_pubkey_t * my_pubkey,
                 fd_pubkey_t * coordinator_pubkey,
                 uchar * out_buf,
                 ulong * out_buf_len ) {
  ulong root_idx;
  restart->funk_root                       = funk_root;
  restart->epoch_schedule                  = epoch_schedule;
  restart->root_epoch                      = fd_slot_to_epoch( epoch_schedule, restart->funk_root, &root_idx ),
  restart->stage                           = WR_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM;
  restart->heaviest_fork_ready             = 0;
  restart->coordinator_heaviest_fork_ready = 0;
  fd_memcpy( restart->root_bank_hash.hash, root_bank_hash, sizeof(fd_pubkey_t) );
  fd_memcpy( restart->my_pubkey.key, my_pubkey, sizeof(fd_pubkey_t) );
  fd_memcpy( restart->coordinator_pubkey.key, coordinator_pubkey, sizeof(fd_pubkey_t) );
  fd_memset( restart->slot_to_stake, 0, sizeof(restart->slot_to_stake) );
  fd_memset( restart->last_voted_fork_slots_received, 0, sizeof(restart->last_voted_fork_slots_received) );
  FD_LOG_WARNING(( "fd_restart_init:\nfunk root=%lu\nroot epoch=%lu\nroot_bank_hash=%s\ncoordinator pubkey: %s\nMy pubkey: %s",
                    restart->funk_root,
                    restart->root_epoch,
                    FD_BASE58_ENC_32_ALLOCA( &restart->root_bank_hash ),
                    FD_BASE58_ENC_32_ALLOCA( &restart->coordinator_pubkey ),
                    FD_BASE58_ENC_32_ALLOCA( &restart->my_pubkey ) ));

  /* Save the vote accounts stake information for the MAX_EPOCH epochs */
  FD_TEST( RESTART_EPOCHS_MAX==2 );
  for( ulong e=0; e<RESTART_EPOCHS_MAX; e++ ) {
    if( epoch_stakes[e]->vote_accounts_root==NULL ) FD_LOG_ERR(( "vote account information for epoch#%lu is missing", restart->root_epoch+e ));
    restart->num_vote_accts[e]                 = fd_stake_weights_by_node( epoch_stakes[e], restart->stake_weights[e] );
    restart->total_stake[e]                    = 0;
    restart->total_stake_received[e]           = 0;
    restart->total_stake_received_and_voted[e] = 0;
    FD_TEST( restart->num_vote_accts[e]<=MAX_RESTART_PEERS );

    for( ulong i=0; i<restart->num_vote_accts[e]; i++ ) {
      FD_LOG_DEBUG(( "epoch#%lu voter: %s holds stake amount=%lu",
                      restart->root_epoch+e,
                      FD_BASE58_ENC_32_ALLOCA( &restart->stake_weights[e][i].key ),
                      restart->stake_weights[e][i].stake ));
      restart->total_stake[e] += restart->stake_weights[e][i].stake;
    }
    FD_LOG_NOTICE(( "There are %lu staked voters in epoch#%lu with total stake %lu", restart->num_vote_accts[e], restart->root_epoch+e, restart->total_stake[e] ));
  }

  /* Get last_voted_slot and its bank hash for the last_voted_fork_slots gossip message */
  ulong rsz;
  fd_hash_t tower_bank_hash;
  FD_TEST( 0==fd_io_read( tower_checkpt_fileno, &tower_bank_hash, sizeof(fd_hash_t), sizeof(fd_hash_t), &rsz ) );
  FD_TEST( rsz==sizeof(fd_hash_t) );
  ulong tower_height, tower_slots[ FD_TOWER_VOTE_MAX+1 ];
  FD_TEST( 0==fd_io_read( tower_checkpt_fileno, &tower_height, sizeof(ulong), sizeof(ulong), &rsz ) );
  FD_TEST( rsz==sizeof(ulong) );
  FD_TEST( tower_height<=FD_TOWER_VOTE_MAX+1 );
  for( ulong i=0; i<tower_height; i++ ) {
    FD_TEST( 0==fd_io_read( tower_checkpt_fileno, tower_slots+i, sizeof(ulong), sizeof(ulong), &rsz ) );
    FD_TEST( rsz==sizeof(ulong) );
  }
  fd_gossip_restart_last_voted_fork_slots_t * msg = (fd_gossip_restart_last_voted_fork_slots_t *) fd_type_pun( out_buf );
  msg->last_voted_slot = tower_slots[tower_height-1];
  fd_memcpy( msg->last_voted_hash.hash, tower_bank_hash.hash, sizeof(fd_hash_t) );
  FD_LOG_NOTICE(( "last_voted_slot=%lu, bank_hash=%s", msg->last_voted_slot, FD_BASE58_ENC_32_ALLOCA( &tower_bank_hash ) ));

  /* Given last_voted_slot, get the bitmap for the last_voted_fork_slots gossip message */
  ulong end_slot   = msg->last_voted_slot;
  uchar * bitmap   = out_buf+sizeof(fd_gossip_restart_last_voted_fork_slots_t);
  ulong start_slot = ( end_slot>LAST_VOTED_FORK_MAX_SLOTS? end_slot-LAST_VOTED_FORK_MAX_SLOTS : 0 );
  ulong num_slots  = end_slot-start_slot+1;
  msg->offsets.discriminant                            = fd_restart_slots_offsets_enum_raw_offsets;
  msg->offsets.inner.raw_offsets.offsets.has_bits      = 1;
  msg->offsets.inner.raw_offsets.offsets.len           = num_slots;
  msg->offsets.inner.raw_offsets.offsets.bits.bits     = bitmap;
  msg->offsets.inner.raw_offsets.offsets.bits.bits_len = ( num_slots-1 )/BITS_PER_UCHAR+1;
  *out_buf_len = sizeof(fd_gossip_restart_last_voted_fork_slots_t)+( num_slots-1 )/BITS_PER_UCHAR+1;
  FD_LOG_NOTICE(( "fd_restart_init: encoding %lu bits in bitmap", num_slots ));

  /* Encode slots from the tower checkpoint into the bitmap */
  for( ulong i=0; i<tower_height; i++ ) {
    ulong offset_from_end = end_slot-tower_slots[i];
    ulong out_idx         = offset_from_end/BITS_PER_UCHAR;
    int out_bit_off       = offset_from_end%BITS_PER_UCHAR;
    bitmap[out_idx] = fd_uchar_set_bit( bitmap[out_idx], out_bit_off );
  }

  /* Encode slots from slot_history into the bitmap */
  if( FD_UNLIKELY( tower_slots[0]!=slot_history->next_slot ) ) {
    FD_LOG_WARNING(( "You may be loading a wrong snapshot in funk.\n \
                      We expect tower root(%lu) to be the same as slot_history->next_slot(%lu)", tower_slots[0], slot_history->next_slot ));
  }

  for( ulong i=start_slot; i<slot_history->next_slot; i++ ) {
    ulong in_idx          = ( i/BITS_PER_ULONG )%( slot_history->bits.bits->blocks_len );
    ulong in_bit_off      = i%BITS_PER_ULONG;

    ulong offset_from_end = end_slot-i;
    ulong out_idx         = offset_from_end/BITS_PER_UCHAR;
    int out_bit_off       = offset_from_end%BITS_PER_UCHAR;

    if( FD_LIKELY( slot_history->bits.bits->blocks[in_idx] & (1UL<<in_bit_off) ) ) {
      /* bit#i in slot_history is 1 */
      bitmap[out_idx] = fd_uchar_set_bit( bitmap[out_idx], out_bit_off );
    } else {
      /* bit#i in slot_history is 0 */
      bitmap[out_idx] = fd_uchar_clear_bit( bitmap[out_idx], out_bit_off );
    }
  }

  ulong found;
  fd_memcpy( msg->from.key, my_pubkey->key, sizeof(fd_pubkey_t) );
  fd_restart_recv_last_voted_fork_slots( restart, msg, &found );
}
