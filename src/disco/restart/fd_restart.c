#include <sys/types.h>
#include <unistd.h>
#include "fd_restart.h"
#include "../../util/fd_util.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#define BITS_PER_UCHAR ( 8*sizeof(uchar) )
#define BITS_PER_ULONG ( 8*sizeof(ulong) )

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
  ulong received[FD_RESTART_EPOCHS_MAX] = { restart->total_stake_received[0]*100/restart->total_stake[0],
                                            restart->total_stake_received[1]*100/restart->total_stake[1] };
  ulong voted[FD_RESTART_EPOCHS_MAX]    = { restart->total_stake_received_and_voted[0]*100/restart->total_stake[0],
                                            restart->total_stake_received_and_voted[1]*100/restart->total_stake[1] };

  for( ulong e=0; e<FD_RESTART_EPOCHS_MAX; e++ ) {
    FD_LOG_NOTICE(( "Epoch%lu: %lu/%lu = %lu%c stake received\n",
                    restart->root_epoch+e, restart->total_stake_received[e], restart->total_stake[e], received[e], '%' ));
    FD_LOG_NOTICE(( "Epoch%lu: %lu/%lu = %lu%c stake voted\n",
                    restart->root_epoch+e, restart->total_stake_received_and_voted[e], restart->total_stake[e], voted[e], '%' ));
  }

  ulong min_active_stake = received[0];
  if( FD_UNLIKELY( voted[1]>=FD_RESTART_WAIT_FOR_NEXT_EPOCH_THRESHOLD_PERCENT ) ) {
    min_active_stake = fd_ulong_min( min_active_stake, received[1] );
  }
  return min_active_stake>=FD_RESTART_WAIT_FOR_SUPERMAJORITY_THRESHOLD_PERCENT;
}

static void
fd_restart_recv_last_voted_fork_slots( fd_restart_t * restart,
                                       fd_gossip_restart_last_voted_fork_slots_t * msg,
                                       ulong * out_heaviest_fork_found ) {
  if( FD_UNLIKELY( restart->stage!=FD_RESTART_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM ) ) return;

  /* Check that funk is not too stale for aggregating this message */
  ulong voted_epoch = fd_slot_to_epoch( restart->epoch_schedule, msg->last_voted_slot, NULL );
  if( FD_UNLIKELY( voted_epoch!=restart->root_epoch && voted_epoch!=restart->root_epoch+1 ) ) {
    FD_LOG_WARNING(( "Ignore last_voted_fork_slots message from validator %s for epoch%lu (because root_epoch=%lu is stale)",
                     FD_BASE58_ENC_32_ALLOCA( &msg->from ), voted_epoch, restart->root_epoch ));
    return;
  }
  if( FD_UNLIKELY( msg->last_voted_slot>=restart->funk_root+FD_RESTART_LAST_VOTED_FORK_MAX_SLOTS ) ) {
    FD_LOG_WARNING(( "Ignore last_voted_fork_slots message for slot=%lu (because funk_root=%lu is stale) from validator %s",
                     msg->last_voted_slot, restart->funk_root, FD_BASE58_ENC_32_ALLOCA( &msg->from ) ));
    return;
  }

  /* Find the message sender from restart->stake_weights */
  fd_pubkey_t * pubkey = &msg->from;
  ulong stake_received[ FD_RESTART_EPOCHS_MAX ] = {0UL, 0UL};

  for( ulong e=0; e<FD_RESTART_EPOCHS_MAX; e++ ) {
    for( ulong i=0; i<restart->num_vote_accts[e]; i++ ) {
      if( FD_UNLIKELY( memcmp( pubkey->key, restart->stake_weights[e][i].key.key, sizeof(fd_pubkey_t) )==0 ) ) {
        if( FD_UNLIKELY( restart->last_voted_fork_slots_received[e][i] ) ) {
          FD_LOG_NOTICE(( "Duplicate last_voted_fork_slots message from validator %s", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
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
    FD_LOG_WARNING(( "Get last_voted_fork_slots message from validator %s with 0 stake", FD_BASE58_ENC_32_ALLOCA( pubkey ) ));
    return;
  }

  /* Decode the bitmap in the message and aggregate validator stake into slot_to_stake */
  /* The gossip tile should have already converted the bitmap into raw format */
  if( FD_UNLIKELY( msg->last_voted_slot+1<msg->offsets.inner.raw_offsets.offsets.len ) ) {
    FD_LOG_WARNING(( "Received invalid last_voted_fork_slot message from validator %s because %lu<%lu",
                     FD_BASE58_ENC_32_ALLOCA( pubkey ), msg->last_voted_slot+1, msg->offsets.inner.raw_offsets.offsets.len ));
  }
  for( ulong i=0; i<msg->offsets.inner.raw_offsets.offsets.len; i++ ) {
    if( FD_UNLIKELY( msg->last_voted_slot<restart->funk_root+i ) ) break;

    ulong slot     = msg->last_voted_slot-i;
    ulong byte_off = i/BITS_PER_UCHAR;
    int   bit_off  = i%BITS_PER_UCHAR;
    int   bit      = fd_uchar_extract_bit( msg->offsets.inner.raw_offsets.offsets.bits.bits[byte_off], bit_off );
    if( FD_LIKELY( bit ) ) {
      ulong offset = slot-restart->funk_root;
      ulong slot_epoch = fd_slot_to_epoch( restart->epoch_schedule, slot, NULL );
      FD_TEST( slot_epoch==restart->root_epoch || slot_epoch==restart->root_epoch+1 );
      restart->slot_to_stake[offset] += stake_received[slot_epoch-restart->root_epoch];
    }
  }

  if( FD_UNLIKELY( fd_restart_recv_enough_stake( restart ) ) ) {
    ulong stake_threshold[ FD_RESTART_EPOCHS_MAX ] = { restart->total_stake_received[0]
                                                       - restart->total_stake[0]*FD_RESTART_HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT/100UL,
                                                       restart->total_stake_received[1]
                                                       - restart->total_stake[1]*FD_RESTART_HEAVIEST_FORK_THRESHOLD_DELTA_PERCENT/100UL };
    /* The subtraction is safe because restart->total_stake_received[0/1] should be at least >(80-9)%==71% at this point */

    restart->heaviest_fork_slot = restart->funk_root;
    for( ulong offset=0; offset<FD_RESTART_LAST_VOTED_FORK_MAX_SLOTS; offset++ ) {
      ulong slot       = restart->funk_root+offset;
      ulong slot_epoch = fd_slot_to_epoch( restart->epoch_schedule, slot, NULL );
      if( slot_epoch>restart->root_epoch+1 ) break;
      if( FD_LIKELY( restart->slot_to_stake[offset]>=stake_threshold[slot_epoch-restart->root_epoch] ) ) {
        restart->heaviest_fork_slot = restart->funk_root+offset;
      }
    }
    FD_LOG_NOTICE(( "[%s] Found heaviest fork slot=%lu", __func__, restart->heaviest_fork_slot ));

    *out_heaviest_fork_found = 1;
    restart->stage           = FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH;
  }
}

static void
fd_restart_recv_heaviest_fork( fd_restart_t * restart,
                               fd_gossip_restart_heaviest_fork_t * msg ) {
  if( FD_LIKELY( memcmp( restart->coordinator_pubkey.key,
                         msg->from.key, sizeof(fd_pubkey_t) )==0 ) ) {
    FD_LOG_WARNING(( "Received a restart_heaviest_fork message: slot=%lu, hash=%s",
                     msg->last_slot, FD_BASE58_ENC_32_ALLOCA( &msg->last_slot_hash ) ));
    fd_memcpy( &restart->coordinator_heaviest_fork_bank_hash, &msg->last_slot_hash, sizeof(fd_hash_t) );
    restart->coordinator_heaviest_fork_slot  = msg->last_slot;
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
                    restart->funk_root, FD_BASE58_ENC_32_ALLOCA( &restart->root_bank_hash ) ));
    fd_memcpy( &restart->heaviest_fork_bank_hash, &restart->root_bank_hash, sizeof(fd_hash_t) );
    restart->heaviest_fork_ready = 1;

    *out_need_repair = 0;
  } else {
    /* Cancel any leftover in-preparation transactions from funk */
    fd_funk_start_write( funk );
    fd_funk_txn_cancel_all( funk, 1 );
    fd_funk_end_write( funk );

    *out_need_repair = 1;
  }
}

void
fd_restart_verify_heaviest_fork( fd_restart_t * restart,
                                 uchar * out_buf,
                                 ulong * out_send ) {
  *out_send = 0;
  if( FD_UNLIKELY( restart->stage!=FD_RESTART_STAGE_FIND_HEAVIEST_FORK_BANK_HASH ) ) return;

  if( FD_UNLIKELY(( restart->heaviest_fork_ready==1 )) ) {
    if( FD_UNLIKELY( memcmp( restart->my_pubkey.key,
                             restart->coordinator_pubkey.key,
                             sizeof(fd_pubkey_t) )==0 ) ) {
      /* I am the wen-restart coordinator */
      *out_send = 1;
    } else if( FD_UNLIKELY( restart->coordinator_heaviest_fork_ready==1 ) ) {
      /* I am not the wen-restart coordinator, but the coordinator message was received */
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
      *out_send = 1;
    }

    if( FD_UNLIKELY( *out_send ) ) {
      fd_gossip_restart_heaviest_fork_t * msg = (fd_gossip_restart_heaviest_fork_t *) fd_type_pun( out_buf );
      msg->observed_stake                     = 0;
      msg->last_slot                          = restart->heaviest_fork_slot;
      fd_memcpy( msg->last_slot_hash.hash, restart->heaviest_fork_bank_hash.hash, sizeof(fd_hash_t) );

      restart->stage = FD_RESTART_STAGE_GENERATE_SNAPSHOT;
      FD_LOG_WARNING(( "Wen-restart succeeds with slot=%lu, bank hash=%s",
                       restart->heaviest_fork_slot, FD_BASE58_ENC_32_ALLOCA( &restart->heaviest_fork_bank_hash ) ));
      /* TODO: insert a hard fork and generate an incremental snapshot */
      /* The incremental snapshot should contain everything from restart->funk_root to restart->heaviest_fork_slot. */

      restart->stage = FD_RESTART_STAGE_DONE;
    }
  }
}

void
fd_restart_convert_runlength_to_raw_bitmap( fd_gossip_restart_last_voted_fork_slots_t * msg,
                                            uchar * out_bitmap,
                                            ulong * out_bitmap_len ) {
  ulong bit_cnt   = 0;
  *out_bitmap_len = 0;
  fd_memset( out_bitmap, 0, FD_RESTART_RAW_BITMAP_BYTES_MAX );

  for ( ulong i=0, bit=1; i<msg->offsets.inner.run_length_encoding.offsets_len; i++ ) {
    ushort cnt = msg->offsets.inner.run_length_encoding.offsets[i].bits;
    if( bit ) {
      for ( ulong pos=bit_cnt; pos<bit_cnt+cnt; pos++ ) {
        if( FD_UNLIKELY( pos/BITS_PER_UCHAR>=FD_RESTART_RAW_BITMAP_BYTES_MAX ) ) {
          /* Invalid message triggering a buffer overflow */
          *out_bitmap_len = FD_RESTART_RAW_BITMAP_BYTES_MAX+1;
          return;
        }
        out_bitmap[pos/BITS_PER_UCHAR] = fd_uchar_set_bit( out_bitmap[pos/BITS_PER_UCHAR], pos%BITS_PER_UCHAR );
      }
    }
    bit            ^= 1;
    bit_cnt        += cnt;
    *out_bitmap_len = (bit_cnt-1)/BITS_PER_UCHAR+1;
  }
  msg->offsets.discriminant                            = fd_restart_slots_offsets_enum_raw_offsets;
  msg->offsets.inner.raw_offsets.offsets.has_bits      = 1;
  msg->offsets.inner.raw_offsets.offsets.len           = bit_cnt;
  msg->offsets.inner.raw_offsets.offsets.bits.bits_len = *out_bitmap_len;
}

void
fd_restart_convert_raw_bitmap_to_runlength( fd_gossip_restart_last_voted_fork_slots_t * msg,
                                            fd_restart_run_length_encoding_inner_t * out_encoding ) {
  ushort cnt         = 0;
  int    last_bit    = 1;
  ulong  offsets_len = 0;
  for( ulong raw_bitmap_iter=0;
       raw_bitmap_iter<msg->offsets.inner.raw_offsets.offsets.len &&
       offsets_len<FD_RESTART_PACKET_BITMAP_BYTES_MAX/sizeof(ushort);
       raw_bitmap_iter++ ) {
    ulong idx = raw_bitmap_iter/BITS_PER_UCHAR;
    int   off = raw_bitmap_iter%BITS_PER_UCHAR;
    int   bit = fd_uchar_extract_bit( msg->offsets.inner.raw_offsets.offsets.bits.bits[idx], off );
    if( FD_LIKELY( bit==last_bit ) ) {
      cnt++;
    } else {
      out_encoding[offsets_len++].bits = cnt;
      cnt                              = 1;
      last_bit                         = bit;
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
  restart->funk_root                       = funk_root;
  restart->epoch_schedule                  = epoch_schedule;
  restart->root_epoch                      = fd_slot_to_epoch( epoch_schedule, restart->funk_root, NULL ),
  restart->stage                           = FD_RESTART_STAGE_FIND_HEAVIEST_FORK_SLOT_NUM;
  restart->heaviest_fork_ready             = 0;
  restart->coordinator_heaviest_fork_ready = 0;
  fd_memcpy( restart->root_bank_hash.hash, root_bank_hash, sizeof(fd_pubkey_t) );
  fd_memcpy( restart->my_pubkey.key, my_pubkey, sizeof(fd_pubkey_t) );
  fd_memcpy( restart->coordinator_pubkey.key, coordinator_pubkey, sizeof(fd_pubkey_t) );
  fd_memset( restart->slot_to_stake, 0, sizeof(restart->slot_to_stake) );
  fd_memset( restart->last_voted_fork_slots_received, 0, sizeof(restart->last_voted_fork_slots_received) );
  FD_LOG_WARNING(( "[%s]\nfunk root=%lu\nroot epoch=%lu\nroot_bank_hash=%s\ncoordinator pubkey: %s\nMy pubkey: %s",
                    __func__,
                    restart->funk_root,
                    restart->root_epoch,
                    FD_BASE58_ENC_32_ALLOCA( &restart->root_bank_hash ),
                    FD_BASE58_ENC_32_ALLOCA( &restart->coordinator_pubkey ),
                    FD_BASE58_ENC_32_ALLOCA( &restart->my_pubkey ) ));

  /* Save the vote accounts stake information for the MAX_EPOCH epochs */
  FD_TEST( FD_RESTART_EPOCHS_MAX==2 );
  for( ulong e=0; e<FD_RESTART_EPOCHS_MAX; e++ ) {
    if( epoch_stakes[e]->vote_accounts_root==NULL ) FD_LOG_ERR(( "vote account information is missing for epoch#%lu", restart->root_epoch+e ));
    restart->num_vote_accts[e]                 = fd_stake_weights_by_node( epoch_stakes[e], restart->stake_weights[e] );
    restart->total_stake[e]                    = 0;
    restart->total_stake_received[e]           = 0;
    restart->total_stake_received_and_voted[e] = 0;
    FD_TEST( restart->num_vote_accts[e]<=FD_RESTART_MAX_PEERS );

    for( ulong i=0; i<restart->num_vote_accts[e]; i++ ) {
      FD_LOG_DEBUG(( "Epoch#%lu voter %s holds stake amount=%lu",
                      restart->root_epoch+e,
                      FD_BASE58_ENC_32_ALLOCA( &restart->stake_weights[e][i].key ),
                      restart->stake_weights[e][i].stake ));
      restart->total_stake[e] += restart->stake_weights[e][i].stake;
    }
    FD_LOG_NOTICE(( "[%s] There are %lu staked voters in epoch#%lu with total stake %lu",
                    __func__, restart->num_vote_accts[e], restart->root_epoch+e, restart->total_stake[e] ));
  }

  /* Get the last_voted_slot and its bank hash from the tower checkpoint file */
  fd_hash_t tower_bank_hash;
  ulong tower_height, tower_slots[ FD_TOWER_VOTE_MAX+1 ];
  fd_restart_tower_restore( &tower_bank_hash, tower_slots, &tower_height, tower_checkpt_fileno );

  fd_gossip_restart_last_voted_fork_slots_t * msg = (fd_gossip_restart_last_voted_fork_slots_t *) fd_type_pun( out_buf );
  msg->last_voted_slot = tower_slots[tower_height-1];
  fd_memcpy( msg->last_voted_hash.hash, tower_bank_hash.hash, sizeof(fd_hash_t) );

  /* Given last_voted_slot, get the bitmap for the last_voted_fork_slots gossip message */
  ulong end_slot   = msg->last_voted_slot;
  uchar * bitmap   = out_buf+sizeof(fd_gossip_restart_last_voted_fork_slots_t);
  ulong start_slot = ( end_slot>FD_RESTART_LAST_VOTED_FORK_MAX_SLOTS? end_slot-FD_RESTART_LAST_VOTED_FORK_MAX_SLOTS : 0 );
  ulong num_slots  = end_slot-start_slot+1;
  msg->offsets.discriminant                            = fd_restart_slots_offsets_enum_raw_offsets;
  msg->offsets.inner.raw_offsets.offsets.has_bits      = 1;
  msg->offsets.inner.raw_offsets.offsets.len           = num_slots;
  msg->offsets.inner.raw_offsets.offsets.bits.bits     = bitmap;
  msg->offsets.inner.raw_offsets.offsets.bits.bits_len = ( num_slots-1 )/BITS_PER_UCHAR+1;
  *out_buf_len = sizeof(fd_gossip_restart_last_voted_fork_slots_t)+( num_slots-1 )/BITS_PER_UCHAR+1;
  FD_LOG_NOTICE(( "[%s] last_voted_slot=%lu, bank_hash=%s, encoding %lu bits in bitmap",
                  __func__, msg->last_voted_slot, FD_BASE58_ENC_32_ALLOCA( &tower_bank_hash ), num_slots ));

  /* Encode slots from the tower checkpoint into the bitmap */
  for( ulong i=0; i<tower_height; i++ ) {
    ulong offset_from_end = end_slot-tower_slots[i];
    ulong out_idx         = offset_from_end/BITS_PER_UCHAR;
    int   out_bit_off     = offset_from_end%BITS_PER_UCHAR;
    bitmap[out_idx]       = fd_uchar_set_bit( bitmap[out_idx], out_bit_off );
  }

  /* Encode slots from the slot_history system program into the bitmap */
  if( FD_UNLIKELY( tower_slots[0]!=slot_history->next_slot ) ) {
    FD_LOG_WARNING(( "You may be loading a wrong snapshot in funk.\n \
                      We expect tower root(%lu) to be the same as slot_history->next_slot(%lu)", tower_slots[0], slot_history->next_slot ));
  }

  for( ulong i=start_slot; i<slot_history->next_slot; i++ ) {
    ulong in_idx          = ( i/BITS_PER_ULONG )%( slot_history->bits.bits->blocks_len );
    int   in_bit_off      = i%BITS_PER_ULONG;

    ulong offset_from_end = end_slot-i;
    ulong out_idx         = offset_from_end/BITS_PER_UCHAR;
    int   out_bit_off     = offset_from_end%BITS_PER_UCHAR;

    if( FD_LIKELY( fd_ulong_extract_bit( slot_history->bits.bits->blocks[in_idx], in_bit_off ) ) ) {
      /* bit#i in slot_history is 1 */
      bitmap[out_idx] = fd_uchar_set_bit( bitmap[out_idx], out_bit_off );
    } else {
      /* bit#i in slot_history is 0 */
      bitmap[out_idx] = fd_uchar_clear_bit( bitmap[out_idx], out_bit_off );
    }
  }

  ulong found = 0;
  fd_memcpy( msg->from.key, my_pubkey->key, sizeof(fd_pubkey_t) );
  fd_restart_recv_last_voted_fork_slots( restart, msg, &found );
  if( FD_UNLIKELY( found ) ) FD_LOG_WARNING(( "[%s] It seems that this single validator alone has >80% stake", __func__ ));
}

void
fd_restart_tower_checkpt( fd_hash_t const * vote_bank_hash,
                          fd_tower_t * tower,
                          int tower_checkpt_fileno ) {
    lseek( tower_checkpt_fileno, 0, SEEK_SET );
    ulong wsz, total_wsz = 0;
    ulong slots_cnt = fd_tower_votes_cnt( tower->votes )+1;

    fd_io_write( tower_checkpt_fileno, vote_bank_hash, sizeof(fd_hash_t), sizeof(fd_hash_t), &wsz );
    if( FD_UNLIKELY( wsz!=sizeof(fd_hash_t) ) ) goto checkpt_finish;
    total_wsz += wsz;
    fd_io_write( tower_checkpt_fileno, &slots_cnt, sizeof(ulong), sizeof(ulong), &wsz );
    if( FD_UNLIKELY( wsz!=sizeof(ulong) ) ) goto checkpt_finish;
    total_wsz += wsz;
    fd_io_write( tower_checkpt_fileno, &tower->root, sizeof(ulong), sizeof(ulong), &wsz );
    if( FD_UNLIKELY( wsz!=sizeof(ulong) ) ) goto checkpt_finish;
    total_wsz += wsz;

    for( fd_tower_votes_iter_t tower_iter = fd_tower_votes_iter_init( tower->votes );
         !fd_tower_votes_iter_done( tower->votes, tower_iter );
         tower_iter = fd_tower_votes_iter_next( tower->votes, tower_iter ) ) {
      ulong slot = fd_tower_votes_iter_ele( tower->votes, tower_iter )->slot;
      fd_io_write( tower_checkpt_fileno, &slot, sizeof(ulong), sizeof(ulong), &wsz );
      if( FD_UNLIKELY( wsz!=sizeof(ulong) ) ) goto checkpt_finish;
      total_wsz += wsz;
    }

    fsync( tower_checkpt_fileno );
    checkpt_finish:
    if( FD_UNLIKELY( total_wsz!=sizeof(fd_hash_t)+sizeof(ulong)*( slots_cnt+1 ) ) ) FD_LOG_WARNING(( "Failed at checkpointing tower" ));
}

void
fd_restart_tower_restore( fd_hash_t * vote_bank_hash,
                          ulong * tower_slots,
                          ulong * tower_height,
                          int tower_checkpt_fileno ) {
  ulong rsz;
  FD_TEST( 0==fd_io_read( tower_checkpt_fileno, vote_bank_hash, sizeof(fd_hash_t), sizeof(fd_hash_t), &rsz ) );
  FD_TEST( rsz==sizeof(fd_hash_t) );
  FD_TEST( 0==fd_io_read( tower_checkpt_fileno, tower_height, sizeof(ulong), sizeof(ulong), &rsz ) );
  FD_TEST( rsz==sizeof(ulong) );
  FD_TEST( *tower_height<=FD_TOWER_VOTE_MAX+1 );
  for( ulong i=0; i<*tower_height; i++ ) {
    FD_TEST( 0==fd_io_read( tower_checkpt_fileno, tower_slots+i, sizeof(ulong), sizeof(ulong), &rsz ) );
    FD_TEST( rsz==sizeof(ulong) );
  }
}
