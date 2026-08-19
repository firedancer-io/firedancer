#include "fd_footer_rewards.h"

#include "../../ballet/txn/fd_compact_u16.h"
#include "../../flamenco/runtime/fd_accdb_svm.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

/* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/votor-messages/src/reward_certificate.rs#L20 */
#define NUM_SLOTS_FOR_REWARD (8UL)

#define RANK_SET_WORDS ((AG_VAT_MAX+63UL)/64UL)

FD_STATIC_ASSERT( MAX_EPOCH_CREDITS_HISTORY==64UL, epoch_credits_bound );

/* signer_bitmap_ranks decodes a solana-signer-store bitmap (version
   (1) | bit count (u16 LE) | payload) into a rank bit set.  Only base2
   bitmaps are accepted: Agave rejects base3 bitmaps for finalization
   certs and only verifies reward certs with verify_base2. */

static int
signer_bitmap_ranks( uchar const * bitmap,
                     ulong         bitmap_sz,
                     ulong *       set ) {
  if( FD_UNLIKELY( bitmap_sz<3UL     ) ) return -1;
  if( FD_UNLIKELY( bitmap[0]!=0      ) ) return -1; /* base2 */
  ulong nbits = (ulong)FD_LOAD( ushort, bitmap+1UL );
  if( FD_UNLIKELY( nbits>AG_VAT_MAX  ) ) return -1;
  if( FD_UNLIKELY( bitmap_sz-3UL!=(nbits+7UL)/8UL ) ) return -1;
  uchar const * payload = bitmap+3UL;
  for( ulong r=0UL; r<nbits; r++ ) {
    if( payload[ r>>3 ] & (uchar)(1U<<(r&7U)) ) set[ r>>6 ] |= 1UL<<(r&63UL);
  }
  return 0;
}

/* final_cert_parse walks a BlockFinalizationCert (see
   fd_block_marker.h for the layout) and returns the cert slot and its
   one (fast finalization) or two (slow finalization) aggregate
   bitmaps. */

static int
final_cert_parse( uchar const *  buf,
                  ulong          sz,
                  ulong *        slot,
                  uchar const *  bitmap[ 2 ],
                  ulong          bitmap_sz[ 2 ],
                  ulong *        bitmap_cnt ) {
  if( FD_UNLIKELY( sz<8UL+sizeof(fd_hash_t) ) ) return -1;
  *slot = FD_LOAD( ulong, buf );
  ulong off = 8UL+sizeof(fd_hash_t);

  *bitmap_cnt = 0UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_UNLIKELY( sz<off+96UL+2UL ) ) return -1;
    ulong bl = (ulong)FD_LOAD( ushort, buf+off+96UL );
    off += 96UL+2UL;
    if( FD_UNLIKELY( sz<off+bl ) ) return -1;
    bitmap[ i ]    = buf+off;
    bitmap_sz[ i ] = bl;
    off += bl;
    (*bitmap_cnt)++;
    if( i==0UL ) {
      if( FD_UNLIKELY( sz<off+1UL ) ) return -1;
      uchar has_notar = buf[ off++ ];
      if( FD_UNLIKELY( has_notar>1 ) ) return -1;
      if( !has_notar ) break;
    }
  }
  return 0;
}

/* reward_cert_parse walks a SkipRewardCertificate (block_id_sz 0) or
   NotarRewardCertificate (block_id_sz 32):

     slot (8) | [block_id (32)] | compressed BLS signature (96) |
     bitmap byte count (ShortU16) | bitmap */

static int
reward_cert_parse( uchar const *  buf,
                   ulong          sz,
                   ulong          block_id_sz,
                   ulong *        slot,
                   uchar const ** bitmap,
                   ulong *        bitmap_sz ) {
  ulong off = 8UL+block_id_sz+96UL;
  if( FD_UNLIKELY( sz<off+1UL ) ) return -1;
  *slot = FD_LOAD( ulong, buf );
  ulong cu16_sz = fd_cu16_dec_sz( buf+off, sz-off );
  if( FD_UNLIKELY( !cu16_sz ) ) return -1;
  ulong bl = (ulong)fd_cu16_dec_fixed( buf+off, cu16_sz );
  off += cu16_sz;
  if( FD_UNLIKELY( sz<off+bl ) ) return -1;
  *bitmap    = buf+off;
  *bitmap_sz = bl;
  return 0;
}

/* inflation_reward_for_epoch reads the EpochInflationAccountState
   account (wincode: current (u64 reward, u64 slots_per_epoch, u64
   epoch) | has_prev (u8) | [prev, same shape]) and returns the state
   recorded for epoch.  Returns -1 if the account or the epoch's state
   is missing. */

static int
inflation_reward_for_epoch( fd_bank_t *         bank,
                            fd_accdb_t *        accdb,
                            fd_pubkey_t const * addr,
                            ulong               epoch,
                            ulong *             max_reward,
                            ulong *             slots_per_epoch ) {
  int      err = -1;
  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, addr->uc );
  if( FD_LIKELY( acc.lamports && acc.data_len>=25UL ) ) {
    if( FD_LOAD( ulong, acc.data+16UL )==epoch ) {
      *max_reward      = FD_LOAD( ulong, acc.data      );
      *slots_per_epoch = FD_LOAD( ulong, acc.data+8UL  );
      err = 0;
    } else if( acc.data[ 24UL ]==1 && acc.data_len>=49UL && FD_LOAD( ulong, acc.data+41UL )==epoch ) {
      *max_reward      = FD_LOAD( ulong, acc.data+25UL );
      *slots_per_epoch = FD_LOAD( ulong, acc.data+33UL );
      err = 0;
    }
  }
  fd_accdb_unread_one( accdb, &acc );
  return err;
}

/* credits_increment mirrors Agave's alpenglow increment_credits
   (vote_reward.rs): accumulate credits into the tail epoch_credits
   entry, starting a new entry on epoch changes and inserting the
   tower->alpenglow migration marker in the migration epoch.  The
   deque's capacity is MAX_EPOCH_CREDITS_HISTORY+1 while Agave pushes
   into an unbounded Vec before trimming, so we drop the head early
   when full; the final trimmed state is the same. */

static void
credits_increment( fd_vote_epoch_credits_t * ec,
                   ulong                     migration_epoch,
                   ulong                     epoch,
                   ulong                     credits /* nonzero */ ) {
  if( epoch==migration_epoch ) {
    int have_marker = 0;
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( ec );
         !deq_fd_vote_epoch_credits_t_iter_done( ec, iter );
         iter = deq_fd_vote_epoch_credits_t_iter_next( ec, iter ) ) {
      if( fd_vote_epoch_credits_is_alpenglow_marker( deq_fd_vote_epoch_credits_t_iter_ele( ec, iter ) ) ) { have_marker = 1; break; }
    }
    if( !have_marker ) {
      if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_full( ec ) ) ) deq_fd_vote_epoch_credits_t_pop_head( ec );
      deq_fd_vote_epoch_credits_t_push_tail( ec, (fd_vote_epoch_credits_t){ .epoch=ULONG_MAX, .credits=ULONG_MAX, .prev_credits=ULONG_MAX } );
    }
  }

  ulong cnt = deq_fd_vote_epoch_credits_t_cnt( ec );
  if( FD_UNLIKELY( !cnt ) ) {
    deq_fd_vote_epoch_credits_t_push_tail( ec, (fd_vote_epoch_credits_t){ .epoch=epoch, .credits=credits, .prev_credits=0UL } );
    return;
  }

  fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_tail( ec );

  if( fd_vote_epoch_credits_is_alpenglow_marker( last ) ) {
    /* If there was a tower entry before the marker, its final credits
       form this entry's initial credits. */
    ulong final_tower_credits = 0UL;
    if( cnt>=2UL ) {
      ulong idx = 0UL;
      for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( ec );
           !deq_fd_vote_epoch_credits_t_iter_done( ec, iter );
           iter = deq_fd_vote_epoch_credits_t_iter_next( ec, iter ) ) {
        if( idx==cnt-2UL ) { final_tower_credits = deq_fd_vote_epoch_credits_t_iter_ele( ec, iter )->credits; break; }
        idx++;
      }
    }
    if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_full( ec ) ) ) deq_fd_vote_epoch_credits_t_pop_head( ec );
    deq_fd_vote_epoch_credits_t_push_tail( ec, (fd_vote_epoch_credits_t){
      .epoch        = epoch,
      .credits      = fd_ulong_sat_add( credits, final_tower_credits ),
      .prev_credits = final_tower_credits } );
    while( deq_fd_vote_epoch_credits_t_cnt( ec )>MAX_EPOCH_CREDITS_HISTORY ) deq_fd_vote_epoch_credits_t_pop_head( ec );
    return;
  }

  if( last->epoch==epoch ) {
    last->credits = fd_ulong_sat_add( last->credits, credits );
    return;
  }

  if( last->credits==last->prev_credits ) {
    /* Different epochs but the latest epoch earned no credits, reuse
       the entry. */
    last->epoch   = epoch;
    last->credits = fd_ulong_sat_add( last->credits, credits );
    return;
  }

  ulong final_credits = last->credits;
  if( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_full( ec ) ) ) deq_fd_vote_epoch_credits_t_pop_head( ec );
  deq_fd_vote_epoch_credits_t_push_tail( ec, (fd_vote_epoch_credits_t){
    .epoch        = epoch,
    .credits      = fd_ulong_sat_add( credits, final_credits ),
    .prev_credits = final_credits } );
  while( deq_fd_vote_epoch_credits_t_cnt( ec )>MAX_EPOCH_CREDITS_HISTORY ) deq_fd_vote_epoch_credits_t_pop_head( ec );
}

/* vs_maybe_update_votes mirrors VoteState::maybe_update_votes: the
   votes deque is replaced by a single landed vote on the latest voted
   slot, and last_timestamp advances to the slot's timestamp if newer. */

static void
vs_maybe_update_votes( fd_vote_state_versioned_t * vs,
                       ulong                       slot,
                       long                        slot_timestamp_ns ) {
  ulong latest = slot;
  ulong const * last_voted = fd_vsv_get_last_voted_slot( vs );
  if( last_voted && *last_voted>latest ) latest = *last_voted;
  ulong const * root = fd_vsv_get_root_slot( vs );
  if( root && *root>latest ) latest = *root;

  fd_landed_vote_t * votes = fd_vsv_get_votes_mutable( vs );
  deq_fd_landed_vote_t_remove_all( votes );
  deq_fd_landed_vote_t_push_tail( votes, (fd_landed_vote_t){ .latency=0, .lockout={ .slot=latest, .confirmation_count=1U } } );

  long timestamp = slot_timestamp_ns/1000000000L;
  if( timestamp>fd_vsv_get_last_timestamp( vs )->timestamp ) {
    fd_vsv_set_last_timestamp( vs, &(fd_vote_block_timestamp_t){ .slot=slot, .timestamp=timestamp } );
  }
}

/* vote_update describes the mutations to apply to one vote account. */

struct vote_update {
  int   update_votes; ulong vote_slot; long vote_ts_ns;
  int   update_root;  ulong root_slot;
  ulong credits;      /* 0 = none */
  ulong migration_epoch;
  ulong current_epoch;
};
typedef struct vote_update vote_update_t;

/* vote_account_modify read-modify-writes the vote account at pk.  Vote
   accounts that are missing or fail to (de)serialize are skipped, like
   Agave's VoteState::try_new / serialize. */

static void
vote_account_modify( fd_bank_t *           bank,
                     fd_accdb_t *          accdb,
                     fd_capture_ctx_t *    capture_ctx,
                     fd_pubkey_t const *   pk,
                     vote_update_t const * upd ) {
  static FD_TL fd_vote_state_versioned_t vs[1];
  static FD_TL uchar                     buf[ 8192UL ];

  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, pk->uc );
  if( FD_UNLIKELY( !acc.lamports || acc.data_len>sizeof(buf) ) ) {
    fd_accdb_unread_one( accdb, &acc );
    FD_BASE58_ENCODE_32_BYTES( pk->uc, pk_b58 );
    FD_LOG_WARNING(( "slot %lu: footer rewards: vote account %s missing; skipping", bank->f.slot, pk_b58 ));
    return;
  }
  if( FD_UNLIKELY( fd_vsv_deserialize( &acc, vs ) ) ) {
    fd_accdb_unread_one( accdb, &acc );
    FD_BASE58_ENCODE_32_BYTES( pk->uc, pk_b58 );
    FD_LOG_WARNING(( "slot %lu: footer rewards: vote account %s failed to deserialize; skipping", bank->f.slot, pk_b58 ));
    return;
  }
  ulong       data_len = acc.data_len;
  fd_pubkey_t owner;
  fd_memcpy( owner.uc, acc.owner, sizeof(fd_pubkey_t) );
  fd_accdb_unread_one( accdb, &acc );

  /* Order matters: reward-cert mutations run before final-cert
     mutations in Agave, and votes derive from the current root. */
  if( upd->update_votes ) vs_maybe_update_votes( vs, upd->vote_slot, upd->vote_ts_ns );
  if( upd->update_root ) {
    ulong const * root = fd_vsv_get_root_slot( vs );
    ulong latest_root  = fd_ulong_max( root ? *root : upd->root_slot, upd->root_slot );
    fd_vsv_set_root_slot( vs, &latest_root );
  }
  if( upd->credits ) credits_increment( fd_vsv_get_epoch_credits_mutable( vs ), upd->migration_epoch, upd->current_epoch, upd->credits );

  fd_memset( buf, 0, data_len );
  if( FD_UNLIKELY( fd_vote_state_versioned_serialize( vs, buf, data_len ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( pk->uc, pk_b58 );
    FD_LOG_WARNING(( "slot %lu: footer rewards: vote account %s failed to serialize; skipping", bank->f.slot, pk_b58 ));
    return;
  }
  fd_accdb_svm_write( bank, accdb, capture_ctx, pk, &owner, buf, data_len, 0UL, 0 );
}

/* slot_timestamp mirrors calc_slot_timestamp: the footer timestamp
   backdated by the duration of slots (slot, bank_slot].  Assumes slot
   duration params do not transition inside the window (TODO). */

static long
slot_timestamp( fd_bank_t * bank,
                ulong       slot,
                ulong       footer_time_nanos ) {
  ulong dur = fd_ulong_sat_mul( bank->f.slot-slot, bank->f.slot_params.ns_per_slot );
  return (long)footer_time_nanos - (long)dur;
}

int
fd_footer_rewards_apply( fd_bank_t *               bank,
                         fd_accdb_t *              accdb,
                         fd_capture_ctx_t *        capture_ctx,
                         fd_footer_certs_t const * certs,
                         ulong                     footer_time_nanos,
                         ulong                     migration_slot,
                         fd_pubkey_t const *       leader_vote_pubkey,
                         fd_pubkey_t const *       vote_reward_acct_addr,
                         fd_footer_epoch_info_fn_t epoch_info_fn,
                         void *                    epoch_info_ctx ) {
  ulong bank_slot       = bank->f.slot;
  ulong current_epoch   = fd_slot_to_epoch( &bank->f.epoch_schedule, bank_slot,      NULL );
  ulong migration_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, migration_slot, NULL );
  ulong leader_credits  = 0UL;

  /* ---- reward certs: credits for the attested voters of the reward
          slot ---- */

  if( certs->skip_reward_cert || certs->notar_reward_cert ) {
    ulong reward_set[ RANK_SET_WORDS ] = {0};
    ulong skip_slot = ULONG_MAX, notar_slot = ULONG_MAX;
    if( certs->skip_reward_cert ) {
      uchar const * bitmap; ulong bitmap_sz;
      if( FD_UNLIKELY( reward_cert_parse( certs->skip_reward_cert, certs->skip_reward_cert_sz, 0UL, &skip_slot, &bitmap, &bitmap_sz ) ||
                       signer_bitmap_ranks( bitmap, bitmap_sz, reward_set ) ) ) {
        FD_LOG_WARNING(( "slot %lu: malformed skip reward cert", bank_slot ));
        return -1;
      }
    }
    if( certs->notar_reward_cert ) {
      uchar const * bitmap; ulong bitmap_sz;
      if( FD_UNLIKELY( reward_cert_parse( certs->notar_reward_cert, certs->notar_reward_cert_sz, sizeof(fd_hash_t), &notar_slot, &bitmap, &bitmap_sz ) ||
                       signer_bitmap_ranks( bitmap, bitmap_sz, reward_set ) ) ) {
        FD_LOG_WARNING(( "slot %lu: malformed notar reward cert", bank_slot ));
        return -1;
      }
    }
    if( FD_UNLIKELY( skip_slot!=ULONG_MAX && notar_slot!=ULONG_MAX && skip_slot!=notar_slot ) ) {
      FD_LOG_WARNING(( "slot %lu: reward cert slots differ: skip %lu, notar %lu", bank_slot, skip_slot, notar_slot ));
      return -1;
    }
    ulong reward_slot = fd_ulong_min( skip_slot, notar_slot );
    if( FD_UNLIKELY( fd_ulong_sat_add( reward_slot, NUM_SLOTS_FOR_REWARD )!=bank_slot || reward_slot<=migration_slot ) ) {
      FD_LOG_WARNING(( "slot %lu: invalid reward cert slot %lu (migration slot %lu)", bank_slot, reward_slot, migration_slot ));
      return -1;
    }

    ag_epoch_info_t const * info = epoch_info_fn( epoch_info_ctx, fd_slot_to_epoch( &bank->f.epoch_schedule, reward_slot, NULL ) );
    if( FD_UNLIKELY( !info ) ) {
      FD_LOG_WARNING(( "slot %lu: no validator set for reward slot %lu", bank_slot, reward_slot ));
      return -1;
    }
    ulong max_reward, slots_per_epoch;
    if( FD_UNLIKELY( !vote_reward_acct_addr ||
                     inflation_reward_for_epoch( bank, accdb, vote_reward_acct_addr, fd_slot_to_epoch( &bank->f.epoch_schedule, reward_slot, NULL ), &max_reward, &slots_per_epoch ) ) ) {
      FD_LOG_WARNING(( "slot %lu: no epoch inflation state for reward slot %lu", bank_slot, reward_slot ));
      return -1;
    }

    long ts_ns = slot_timestamp( bank, reward_slot, footer_time_nanos );
    for( ulong r=0UL; r<info->validator_cnt; r++ ) {
      if( !( reward_set[ r>>6 ] & (1UL<<(r&63UL)) ) ) continue;
      /* per-slot, stake-fractional reward; split half validator, half
         (rounded up) leader */
      uint128 numerator   = (uint128)max_reward*(uint128)info->validators[ r ].stake;
      uint128 denominator = (uint128)slots_per_epoch*(uint128)info->total_stake;
      ulong   reward      = denominator ? (ulong)( numerator/denominator ) : 0UL;
      ulong   validator_reward = reward/2UL;
      leader_credits = fd_ulong_sat_add( leader_credits, reward-validator_reward );

      vote_update_t upd = {
        .update_votes    = 1, .vote_slot = reward_slot, .vote_ts_ns = ts_ns,
        .credits         = validator_reward,
        .migration_epoch = migration_epoch,
        .current_epoch   = current_epoch,
      };
      vote_account_modify( bank, accdb, capture_ctx, &info->validators[ r ].vote_pubkey, &upd );
    }
  }

  /* ---- finalization cert: root/votes/timestamp for the signers ---- */

  if( certs->final_cert ) {
    ulong         final_slot;
    uchar const * bitmap[ 2 ];
    ulong         bitmap_sz[ 2 ];
    ulong         bitmap_cnt;
    ulong         final_set[ RANK_SET_WORDS ] = {0};
    if( FD_UNLIKELY( final_cert_parse( certs->final_cert, certs->final_cert_sz, &final_slot, bitmap, bitmap_sz, &bitmap_cnt ) ) ) {
      FD_LOG_WARNING(( "slot %lu: malformed footer finalization cert", bank_slot ));
      return -1;
    }
    for( ulong i=0UL; i<bitmap_cnt; i++ ) {
      if( FD_UNLIKELY( signer_bitmap_ranks( bitmap[ i ], bitmap_sz[ i ], final_set ) ) ) {
        FD_LOG_WARNING(( "slot %lu: malformed footer finalization cert bitmap", bank_slot ));
        return -1;
      }
    }

    ag_epoch_info_t const * info = epoch_info_fn( epoch_info_ctx, fd_slot_to_epoch( &bank->f.epoch_schedule, final_slot, NULL ) );
    if( FD_UNLIKELY( !info ) ) {
      FD_LOG_WARNING(( "slot %lu: no validator set for finalized slot %lu", bank_slot, final_slot ));
      return -1;
    }

    long ts_ns = slot_timestamp( bank, final_slot, footer_time_nanos );
    for( ulong r=0UL; r<info->validator_cnt; r++ ) {
      if( !( final_set[ r>>6 ] & (1UL<<(r&63UL)) ) ) continue;
      vote_update_t upd = {
        .update_root  = 1, .root_slot = final_slot,
        .update_votes = 1, .vote_slot = final_slot, .vote_ts_ns = ts_ns,
      };
      vote_account_modify( bank, accdb, capture_ctx, &info->validators[ r ].vote_pubkey, &upd );
    }
  }

  /* ---- leader rewards ---- */

  if( leader_credits ) {
    if( FD_UNLIKELY( !leader_vote_pubkey ) ) {
      FD_LOG_WARNING(( "slot %lu: leader vote account unknown; dropping %lu leader reward credits (bank hash will diverge)", bank_slot, leader_credits ));
    } else {
      vote_update_t upd = {
        .credits         = leader_credits,
        .migration_epoch = migration_epoch,
        .current_epoch   = current_epoch,
      };
      vote_account_modify( bank, accdb, capture_ctx, leader_vote_pubkey, &upd );
    }
  }

  return 0;
}