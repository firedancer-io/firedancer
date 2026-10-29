#include "fd_alpenglow.h"
#include "fd_vote_queue.h"
#include "../rewards/fd_epoch_inflation_account.h"

#include "../runtime/fd_hashes.h"
#include "../runtime/fd_pubkey_utils.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/program/vote/fd_vote_codec_tmpl.h"
#include "../runtime/sysvar/fd_sysvar_clock.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"

FD_STATIC_ASSERT( MAX_EPOCH_CREDITS_HISTORY==64UL, epoch_credits_bound );

static int
vote_stakes_iter_kind_for_epoch( fd_bank_t const * bank,
                                 ulong             epoch ) {
  ulong t_1_epoch = fd_vote_stakes_fork_epoch( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id )+1UL;
  if( FD_UNLIKELY( epoch>t_1_epoch || t_1_epoch-epoch>(ulong)(FD_VOTE_STAKES_ITER_T_5-FD_VOTE_STAKES_ITER_T_1) ) ) return 0;
  return FD_VOTE_STAKES_ITER_T_1+(int)(t_1_epoch-epoch);
}

/* Footer cert verification */

/* TBD: this is a copy of the votor's ag_vote_signing_ser so the runtime
   does not link fd_choreo; keep the two in sync. */

#define VOTE_TAG_NOTAR (1U) /* WireConsensusMessageKind::NotarVote    */
#define VOTE_TAG_FINAL (2U) /* WireConsensusMessageKind::FinalizeVote */
#define VOTE_TAG_SKIP  (3U) /* WireConsensusMessageKind::SkipVote     */

#define VOTE_SIGNING_SER_MAX ( sizeof(uchar) + sizeof(ulong) + sizeof(fd_hash_t) + sizeof(ushort) )
FD_STATIC_ASSERT( VOTE_SIGNING_SER_MAX<=FD_FOOTER_CACHE_MSG_MAX,       footer_cache_msg_max  );
FD_STATIC_ASSERT( VOTE_SIGNING_SER_MAX==FD_ALPENGLOW_CERT_PAYLOAD_MAX, cert_payload_max      );

static ulong
vote_signing_ser( uint          tag,
                  ulong         slot,
                  uchar const * block_hash,
                  ushort        shred_version,
                  uchar         buf[ static VOTE_SIGNING_SER_MAX ] ) {
  ulong off = 0UL;
  buf[ off ] = (uchar)tag;                                                          off += sizeof(uchar);
  FD_STORE( ulong, buf+off, slot );                                                 off += sizeof(ulong);
  if( FD_LIKELY( block_hash ) ) { memcpy( buf+off, block_hash, sizeof(fd_hash_t) ); off += sizeof(fd_hash_t); }
  FD_STORE( ushort, buf+off, shred_version );                                       off += sizeof(ushort);
  return off;
}

struct validator_set {
  ulong          epoch;
  ulong          validator_cnt;          /* 0 if not built */
  ulong          total_stake;
  fd_bls_pub_t   key_sum;                /* sum of all keys, unused for a t-1 set */
  fd_bls_pub_t   bls_keys[ AG_VAT_MAX ]; /* indexed by rank */
  ulong          stakes  [ AG_VAT_MAX ]; /* indexed by rank */
};
typedef struct validator_set validator_set_t;

/* validator_set_for_slot makes set hold the validators of slot's epoch,
   rebuilding it only when the epoch differs from the one it holds.  A
   set built from the t-1 tier is never reused and gets no key sum: t-1
   is fork specific, so two banks in the same epoch can hold different
   t-1 sets.  Returns 1 on success, 0 if the fork cannot address the
   epoch or the bank holds no ranked validators for it. */

static int
validator_set_for_slot( validator_set_t * set,
                        fd_bank_t const * bank,
                        ulong             slot ) {
  ulong  epoch     = fd_slot_to_epoch( &bank->f.epoch_schedule, slot, NULL );
  ushort fork_id   = bank->vote_stakes_fork_id;
  int    iter_kind = vote_stakes_iter_kind_for_epoch( bank, epoch );
  if( FD_UNLIKELY( !iter_kind ) ) {
    FD_LOG_WARNING(( "slot %lu: cert epoch %lu is not t-1 through t-5", bank->f.slot, epoch ));
    return 0;
  }
  if( FD_LIKELY( iter_kind!=FD_VOTE_STAKES_ITER_T_1 && set->validator_cnt && set->epoch==epoch ) ) return 1;

  set->validator_cnt = 0UL;
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong cnt      = 0UL;
  ulong max_rank = 0UL;
  ulong total    = 0UL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, iter_kind, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, fork_id, iter_kind, iter );
       fd_vote_stakes_iter_next( vote_stakes, fork_id, iter_kind, iter ) ) {
    fd_vote_stakes_ele_t ele[1];
    fd_vote_stakes_iter_ele( vote_stakes, fork_id, iter_kind, iter, ele );
    if( FD_UNLIKELY( ele->rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL ) ) continue;
    FD_TEST( ele->rank<AG_VAT_MAX );

    /* finalize subgroup-checked each ranked key while producing this
       uncompressed encoding, so do not repeat that expensive check here. */
    if( FD_UNLIKELY( fd_bls_pub_de_unchecked( set->bls_keys+ele->rank, ele->bls_key_uncompressed ) ) ) {
      FD_LOG_WARNING(( "slot %lu: rank %u of epoch %lu has a malformed BLS key", bank->f.slot, ele->rank, epoch ));
      return 0;
    }
    set->stakes[ ele->rank ] = ele->stake;
    max_rank = fd_ulong_max( max_rank, (ulong)ele->rank );
    total   += ele->stake;
    cnt++;
  }
  if( FD_UNLIKELY( !cnt || cnt!=max_rank+1UL ) ) {
    FD_LOG_WARNING(( "slot %lu: epoch %lu has %lu ranked validators, highest rank %lu", bank->f.slot, epoch, cnt, max_rank ));
    return 0;
  }
  if( FD_LIKELY( iter_kind!=FD_VOTE_STAKES_ITER_T_1 ) ) {
    fd_bls_set_t all[ fd_bls_set_word_cnt ];
    fd_bls_pub_sum( &set->key_sum, set->bls_keys, fd_bls_set_range( all, 0UL, cnt ) );
  }
  set->epoch         = iter_kind==FD_VOTE_STAKES_ITER_T_1 ? ULONG_MAX : epoch;
  set->validator_cnt = cnt;
  set->total_stake   = total;
  return 1;
}

ulong
fd_alpenglow_cert_payload( fd_block_footer_cert_t const * cert,
                           uint                           vote_tag,
                           ushort                         shred_version,
                           uchar                          payload[ static FD_ALPENGLOW_CERT_PAYLOAD_MAX ] ) {
  return vote_signing_ser( vote_tag, cert->slot, vote_tag==VOTE_TAG_NOTAR ? cert->block_id.uc : NULL, shred_version, payload );
}

int
fd_alpenglow_cert_verify( fd_bank_t const *              bank,
                          fd_block_footer_cert_t const * cert,
                          uint                           vote_tag,
                          ulong                          quorum_numer,
                          ushort                         shred_version,
                          fd_footer_cache_t *            cache,
                          fd_bls_hash_t const *         hm,
                          fd_bls_hash_t *               hm_out ) {
  ulong bank_slot = bank->f.slot;
  ulong cert_slot = cert->slot;

  if( FD_UNLIKELY( !shred_version ) ) {
    FD_LOG_WARNING(( "slot %lu: footer carries certs but the shred version is not known yet; cannot verify them", bank_slot ));
    return -1;
  }

  /* ~200 KiB, kept across calls: consecutive blocks' certs almost
     always share a ring epoch; a fork specific t-1 set is not reused */
  static FD_TL validator_set_t set[1];

  if( FD_UNLIKELY( !validator_set_for_slot( set, bank, cert_slot ) ) ) return -1;

  ulong last_rank = fd_bls_set_last( cert->signer_set ); /* ULONG_MAX when empty */
  if( FD_UNLIKELY( cert->nbits>set->validator_cnt || last_rank>=set->validator_cnt ) ) {
    FD_LOG_WARNING(( "slot %lu: footer cert for slot %lu names %u ranks (highest signer %lu) but its epoch has %lu validators",
                     bank_slot, cert_slot, cert->nbits, last_rank, set->validator_cnt ));
    return -1;
  }

  ulong stake = 0UL;
  for( ulong rank=fd_bls_set_const_iter_init( cert->signer_set ); !fd_bls_set_const_iter_done( rank ); rank=fd_bls_set_const_iter_next( cert->signer_set, rank ) ) {
    stake += set->stakes[ rank ];
  }
  fd_bls_pub_t pub[1];
  fd_bls_pub_sum_cached( pub, set->bls_keys, set->validator_cnt, cert->signer_set,
                         set->epoch!=ULONG_MAX ? &set->key_sum : NULL );
  if( FD_UNLIKELY( quorum_numer && (uint128)stake*(uint128)AG_QUORUM_THRESHOLD_DENOM<(uint128)set->total_stake*(uint128)quorum_numer ) ) {
    FD_LOG_WARNING(( "slot %lu: footer cert for slot %lu has %lu of %lu stake, below %lu/%lu",
                     bank_slot, cert_slot, stake, set->total_stake, quorum_numer, AG_QUORUM_THRESHOLD_DENOM ));
    return -1;
  }

  fd_bls_sig_t sig[1];
  if( FD_UNLIKELY( fd_bls_sig_de_compressed( sig, cert->sig ) ) ) { /* uncompress + g2 subgroup check */
    FD_LOG_WARNING(( "slot %lu: footer cert for slot %lu has a malformed signature", bank_slot, cert_slot ));
    return -1;
  }

  fd_bls_hash_t h[1];
  if( hm ) {
    *h = *hm;
  } else {
    uchar payload[ FD_ALPENGLOW_CERT_PAYLOAD_MAX ];
    ulong payload_sz = fd_alpenglow_cert_payload( cert, vote_tag, shred_version, payload );
    if( cache ) fd_footer_cache_hash_msg( cache, payload, payload_sz, h );
    else        fd_bls_hash_msg( payload, payload_sz, h );
    if( hm_out ) *hm_out = *h;
  }
  if( FD_UNLIKELY( !fd_bls_agg_verify_hashed( h, pub, sig ) ) ) {
    FD_LOG_WARNING(( "slot %lu: footer (is_reward %d) cert for slot %lu failed signature verification", bank_slot, !quorum_numer, cert_slot ));
    return -1;
  }
  return 0;
}

ulong
fd_alpenglow_footer_certs( fd_block_footer_t const *      footer,
                           fd_block_footer_cert_t const * cert  [ static FD_ALPENGLOW_FOOTER_CERT_MAX ],
                           uint                           tag   [ static FD_ALPENGLOW_FOOTER_CERT_MAX ],
                           ulong                          quorum[ static FD_ALPENGLOW_FOOTER_CERT_MAX ] ) {
  ulong n = 0UL;
# define PUSH(c,t,q) do { cert[ n ] = (c); tag[ n ] = (t); quorum[ n ] = (q); n++; } while(0)
  if( footer->has_fast_final_cert   ) PUSH( &footer->fast_final_cert,   VOTE_TAG_NOTAR, AG_STRONG_QUORUM_THRESHOLD_NUMER );
  if( footer->has_final_cert        ) {
    PUSH( &footer->final_cert, VOTE_TAG_FINAL, AG_QUORUM_THRESHOLD_NUMER );
    PUSH( &footer->notar_cert, VOTE_TAG_NOTAR, AG_QUORUM_THRESHOLD_NUMER );
  }
  if( footer->has_skip_reward_cert  ) PUSH( &footer->skip_reward_cert,  VOTE_TAG_SKIP,  0UL );
  if( footer->has_notar_reward_cert ) PUSH( &footer->notar_reward_cert, VOTE_TAG_NOTAR, 0UL );
# undef PUSH
  return n;
}

int
fd_alpenglow_footer_verify( fd_bank_t const *         bank,
                            fd_block_footer_t const * footer,
                            ushort                    shred_version,
                            fd_footer_cache_t *       cache ) {
  int has_certs = footer->has_fast_final_cert | footer->has_final_cert | footer->has_skip_reward_cert | footer->has_notar_reward_cert;
  if( FD_LIKELY( !has_certs ) ) return 0;

  fd_block_footer_cert_t const * cert  [ FD_ALPENGLOW_FOOTER_CERT_MAX ];
  uint                           tag   [ FD_ALPENGLOW_FOOTER_CERT_MAX ];
  ulong                          quorum[ FD_ALPENGLOW_FOOTER_CERT_MAX ];
  ulong                          cnt = fd_alpenglow_footer_certs( footer, cert, tag, quorum );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( fd_alpenglow_cert_verify( bank, cert[ i ], tag[ i ], quorum[ i ], shred_version, cache, NULL, NULL ) ) ) return -1;
  }
  return 0;
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

static void
credits_push_v5( fd_vote_state_v5_t *            v5,
                 fd_vote_epoch_credits_t const * ec ) {
  ulong cnt = v5->accumulated_lamports_len;
  if( FD_UNLIKELY( cnt==FD_VOTE_STATE_V5_ACCUMULATED_LAMPORTS_MAX ) ) {
    memmove( v5->accumulated_lamports, v5->accumulated_lamports+1UL, (cnt-1UL)*sizeof(fd_vote_epoch_credits_t) );
    cnt--;
  }
  v5->accumulated_lamports[ cnt ] = *ec;
  v5->accumulated_lamports_len    = (uint)( cnt+1UL );
}

static void
credits_increment_v5( fd_vote_state_v5_t * v5,
                      ulong                migration_epoch,
                      ulong                epoch,
                      ulong                credits ) {
  if( epoch==migration_epoch ) {
    int have_marker = 0;
    for( ulong i=0UL; i<v5->accumulated_lamports_len; i++ ) have_marker |= fd_vote_epoch_credits_is_alpenglow_marker( &v5->accumulated_lamports[ i ] );
    if( !have_marker ) credits_push_v5( v5, &(fd_vote_epoch_credits_t){ .epoch=ULONG_MAX, .credits=ULONG_MAX, .prev_credits=ULONG_MAX } );
  }

  ulong cnt = v5->accumulated_lamports_len;
  if( FD_UNLIKELY( !cnt ) ) {
    credits_push_v5( v5, &(fd_vote_epoch_credits_t){ .epoch=epoch, .credits=credits, .prev_credits=0UL } );
    return;
  }

  fd_vote_epoch_credits_t * last = &v5->accumulated_lamports[ cnt-1UL ];

  if( fd_vote_epoch_credits_is_alpenglow_marker( last ) ) {
    ulong final_tower_credits = cnt>=2UL ? v5->accumulated_lamports[ cnt-2UL ].credits : 0UL;
    credits_push_v5( v5, &(fd_vote_epoch_credits_t){
      .epoch        = epoch,
      .credits      = fd_ulong_sat_add( credits, final_tower_credits ),
      .prev_credits = final_tower_credits } );
    return;
  }

  if( last->epoch==epoch ) {
    last->credits = fd_ulong_sat_add( last->credits, credits );
    return;
  }

  if( last->credits==last->prev_credits ) {
    last->epoch   = epoch;
    last->credits = fd_ulong_sat_add( last->credits, credits );
    return;
  }

  ulong final_credits = last->credits;
  credits_push_v5( v5, &(fd_vote_epoch_credits_t){
    .epoch        = epoch,
    .credits      = fd_ulong_sat_add( credits, final_credits ),
    .prev_credits = final_credits } );
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

static int
vote_account_open( fd_bank_t *                 bank,
                   fd_accdb_t *                accdb,
                   fd_pubkey_t const *         pk,
                   fd_vote_state_versioned_t * vs,
                   fd_acc_t *                  acc ) {
  *acc = fd_accdb_write_one( accdb, bank->accdb_fork_id, pk->uc );
  if( acc->prior_lamports &&
      fd_vsv_is_correct_size_owner_and_init( acc->prior_owner, acc->prior_data, acc->prior_data_len ) &&
      fd_vote_account_is_valid_v5( acc->data, acc->data_len ) ) {
    /* Vote State V5 accounts are updated in-place so no need to
       deserialize. */
    return 1;
  }
  if( FD_UNLIKELY( !acc->prior_lamports ||
                   !fd_vsv_is_correct_size_owner_and_init( acc->prior_owner, acc->prior_data, acc->prior_data_len ) ||
                   !fd_vote_state_versioned_deserialize( vs, acc->prior_data, acc->prior_data_len ) ||
                   vs->kind==fd_vote_state_versioned_enum_uninitialized ) ) {
    fd_accdb_unwrite_one( accdb, acc );
    return 0;
  }
  return 1;
}

static int
vote_account_is_v5( fd_acc_t const * acc ) {
  return FD_LOAD( uint, acc->data )==fd_vote_state_versioned_enum_v5;
}

static void
vote_update_apply_v5( fd_vote_state_v5_t *  v5,
                      vote_update_t const * upd ) {
  if( upd->update_votes ) {
    v5->latest_vote = v5->latest_vote==ULONG_MAX ? upd->vote_slot : fd_ulong_max( upd->vote_slot, v5->latest_vote );
    if( v5->root_slot!=ULONG_MAX ) v5->latest_vote = fd_ulong_max( v5->latest_vote, v5->root_slot );

    long timestamp = upd->vote_ts_ns/1000000000L;
    if( timestamp>v5->last_timestamp.timestamp ) {
      v5->last_timestamp = (fd_vote_block_timestamp_t){ .slot=upd->vote_slot, .timestamp=timestamp };
    }
  }
  if( upd->update_root ) {
    v5->root_slot = v5->root_slot==ULONG_MAX ? upd->root_slot : fd_ulong_max( v5->root_slot, upd->root_slot );
  }
  if( upd->credits ) credits_increment_v5( v5, upd->migration_epoch, upd->current_epoch, upd->credits );
}

static void
vote_update_apply( fd_vote_state_versioned_t * vs,
                   fd_acc_t *                  acc,
                   vote_update_t const *       upd ) {
  if( vote_account_is_v5( acc ) ) {
    vote_update_apply_v5( fd_vote_account_v5( acc->data ), upd );
    return;
  }
  if( upd->update_votes ) vs_maybe_update_votes( vs, upd->vote_slot, upd->vote_ts_ns );
  if( upd->update_root ) {
    ulong const * root = fd_vsv_get_root_slot( vs );
    ulong latest_root  = fd_ulong_max( root ? *root : upd->root_slot, upd->root_slot );
    fd_vsv_set_root_slot( vs, &latest_root );
  }
  if( upd->credits ) credits_increment( fd_vsv_get_epoch_credits_mutable( vs ), upd->migration_epoch, upd->current_epoch, upd->credits );
}

static void
vote_account_store( fd_bank_t *                       bank,
                    fd_accdb_t *                      accdb,
                    fd_capture_ctx_t *                capture_ctx,
                    fd_acc_t *                        acc,
                    fd_vote_state_versioned_t const * vs,
                    fd_footer_cache_memo_t *          memo,
                    fd_vote_queue_t *                 q ) {
  /* We do not need to serialize Vote State V5 accounts as they are
     updated in-place. */
  if( !vote_account_is_v5( acc ) ) {
    fd_memset( acc->data, 0, acc->data_len );
    if( FD_UNLIKELY( fd_vote_state_versioned_serialize( vs, acc->data, acc->data_len ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( acc->pubkey, pk_b58 );
      FD_LOG_WARNING(( "slot %lu: vote account %s failed to serialize; skipping", bank->f.slot, pk_b58 ));
      fd_accdb_unwrite_one( accdb, acc );
      return;
    }
  }
  acc->executable = 0;

  fd_vote_queue_store( q, acc, memo );
  fd_hashes_capture_account( acc->pubkey, acc->owner, acc->lamports, acc->executable, acc->data, acc->data_len, bank, capture_ctx );

  acc->commit = 1;
  fd_accdb_unwrite_one( accdb, acc );
}

static void
vote_account_modify( fd_bank_t *              bank,
                     fd_accdb_t *             accdb,
                     fd_capture_ctx_t *       capture_ctx,
                     fd_pubkey_t const *      pk,
                     vote_update_t const *    upd,
                     fd_footer_cache_memo_t * memo,
                     fd_vote_queue_t *        q ) {
  static FD_TL fd_vote_state_versioned_t vs[1];
  fd_acc_t acc;
  if( FD_UNLIKELY( !vote_account_open( bank, accdb, pk, vs, &acc ) ) ) return;
  vote_update_apply( vs, &acc, upd );
  vote_account_store( bank, accdb, capture_ctx, &acc, vs, memo, q );
}

void
fd_alpenglow_pda( char const *  seed,
                  fd_pubkey_t * out ) {
  fd_pubkey_t const * feature_id = &ids[ offsetof( fd_features_t, alpenglow )>>3 ].id;

  uchar const * seed_   = (uchar const *)seed;
  ulong         seed_sz = strlen( seed );
  uchar         bump;
  uint          custom_err;
  FD_TEST( fd_pubkey_find_program_address( feature_id, 1UL, &seed_, &seed_sz, out, &bump, &custom_err )==FD_PUBKEY_SUCCESS );
}

ulong
fd_alpenglow_migration_slot( fd_bank_t *  bank,
                             fd_accdb_t * accdb ) {
  fd_pubkey_t genesis_cert_addr;
  fd_alpenglow_pda( "carlgration", &genesis_cert_addr );

  ulong    migration_slot = ULONG_MAX;
  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, genesis_cert_addr.uc );
  if( FD_LIKELY( acc.lamports && acc.data_len>=8UL ) ) migration_slot = FD_LOAD( ulong, acc.data );
  fd_accdb_unread_one( accdb, &acc );
  return migration_slot;
}

void
fd_alpenglow_producer_time_bounds( fd_bank_t const * bank,
                                   fd_accdb_t *      accdb,
                                   long *            lo,
                                   long *            hi ) {
  fd_pubkey_t alpenclock_addr;
  fd_alpenglow_pda( "alpenclock", &alpenclock_addr );

  long     parent_nanos;
  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, alpenclock_addr.uc );
  int      has_alpenclock = acc.lamports && acc.data_len>=sizeof(ulong);
  if( FD_LIKELY( has_alpenclock ) ) parent_nanos = (long)FD_LOAD( ulong, acc.data );
  fd_accdb_unread_one( accdb, &acc );
  if( FD_UNLIKELY( !has_alpenclock ) ) {
    fd_sol_sysvar_clock_t clock[1];
    if( FD_UNLIKELY( !fd_sysvar_clock_read( accdb, bank->accdb_fork_id, clock ) ) ) FD_LOG_ERR(( "fd_sysvar_clock_read failed" ));
    parent_nanos = fd_long_sat_mul( clock->unix_timestamp, 1000000000L );
  }

  ulong elapsed = fd_slot_params_slot_range_duration_ns( bank, bank->f.parent_slot+1UL, bank->f.slot+1UL /* inclusive */ );
  *lo = fd_long_sat_add( parent_nanos, 1L );
  *hi = fd_long_sat_add( parent_nanos, (long)fd_ulong_min( fd_ulong_sat_mul( elapsed, 2UL ), (ulong)LONG_MAX ) );
}

/* slot_timestamp backdates the footer timestamp by the duration of
   slots (slot, bank_slot], taking into account reduced slot times.

   https://github.com/anza-xyz/agave/blob/v4.3/runtime/src/block_component_processor/vote_reward.rs#L505 */
static long
slot_timestamp( fd_bank_t * bank,
                ulong       slot,
                ulong       footer_time_nanos ) {
  ulong dur = fd_slot_params_slot_range_duration_ns( bank, slot+1UL, bank->f.slot+1UL );
  return fd_long_sat_sub( (long)footer_time_nanos, (long)dur );
}

static ulong
memo_rank( fd_bank_t const *   bank,
           int                 iter_kind,
           fd_pubkey_t const * pubkey ) {
  fd_vote_stakes_ele_t ele[1];
  int found;
  switch( iter_kind ) {
  case FD_VOTE_STAKES_ITER_T_2: found = fd_vote_stakes_query_t_2( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id, pubkey, ele ); break;
  case FD_VOTE_STAKES_ITER_T_3: found = fd_vote_stakes_query_t_3( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id, pubkey, ele ); break;
  default:                      return ULONG_MAX;
  }
  if( FD_UNLIKELY( !found || ele->rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL ) ) return ULONG_MAX;
  FD_TEST( ele->rank<AG_VAT_MAX );
  return (ulong)ele->rank;
}

int
fd_alpenglow_rewards_apply( fd_bank_t *               bank,
                            fd_accdb_t *              accdb,
                            fd_capture_ctx_t *        capture_ctx,
                            fd_footer_cache_t *       cache,
                            fd_block_footer_t const * footer ) {

  ulong bank_slot         = bank->f.slot;
  ulong footer_time_nanos = footer->block_producer_time_nanos;
  ulong current_epoch     = fd_slot_to_epoch( &bank->f.epoch_schedule, bank_slot, NULL );
  ulong migration_epoch   = ULONG_MAX;
  ulong leader_credits    = 0UL;

  /* credits for the attested voters of the reward slot */

  int          has_reward = footer->has_skip_reward_cert || footer->has_notar_reward_cert;
  int          has_final  = footer->has_fast_final_cert  || footer->has_final_cert;
  fd_bls_set_t reward_set[ fd_bls_set_word_cnt ];
  fd_bls_set_t final_set [ fd_bls_set_word_cnt ];
  ulong        reward_slot     = 0UL;
  ulong        max_reward      = 0UL;
  ulong        slots_per_epoch = 0UL;
  ulong        total_stake     = 0UL;
  long         reward_ts_ns    = 0L;
  int          reward_kind     = 0;
  ulong        final_slot      = 0UL;
  ulong        final_epoch     = 0UL;
  long         final_ts_ns     = 0L;
  int          final_kind      = 0;

  if( has_reward ) {
    fd_bls_set_null( reward_set );
    ulong skip_slot = ULONG_MAX, notar_slot = ULONG_MAX;
    if( footer->has_skip_reward_cert ) {
      skip_slot = footer->skip_reward_cert.slot;
      fd_bls_set_union( reward_set, reward_set, footer->skip_reward_cert.signer_set );
    }
    if( footer->has_notar_reward_cert ) {
      notar_slot = footer->notar_reward_cert.slot;
      fd_bls_set_union( reward_set, reward_set, footer->notar_reward_cert.signer_set );
    }
    if( FD_UNLIKELY( skip_slot!=ULONG_MAX && notar_slot!=ULONG_MAX && skip_slot!=notar_slot ) ) {
      FD_LOG_WARNING(( "slot %lu: reward cert slots differ: skip %lu, notar %lu", bank_slot, skip_slot, notar_slot ));
      return -1;
    }
    reward_slot = fd_ulong_min( skip_slot, notar_slot );

    ulong migration_slot = fd_alpenglow_migration_slot( bank, accdb );
    if( FD_UNLIKELY( migration_slot==ULONG_MAX ) ) {
      FD_LOG_WARNING(( "slot %lu: reward cert but no genesis certificate account", bank_slot ));
      return -1;
    }
    migration_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, migration_slot, NULL );

    if( FD_UNLIKELY( fd_ulong_sat_add( reward_slot, FD_NUM_SLOTS_FOR_REWARD )!=bank_slot || reward_slot<=migration_slot ) ) {
      FD_LOG_WARNING(( "slot %lu: invalid reward cert slot %lu (migration slot %lu)", bank_slot, reward_slot, migration_slot ));
      return -1;
    }

    ulong reward_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, reward_slot, NULL );

    /* Changed to charge rewards against the processing bank's epoch
       inflation budget, not the reward slot's epoch.  Handles rewards
       going over budget when inflation rate decreases.
       https://github.com/anza-xyz/agave/blob/386cf57c45e135d8a3a8b7d16877eb896f695c64/runtime/src/block_component_processor/vote_reward.rs#L194 */
    fd_epoch_inflation_account_state_t inflation[1];
    fd_epoch_inflation_state_t const * inflation_state = NULL;
    if( FD_LIKELY( fd_epoch_inflation_account_read( bank, accdb, inflation ) ) ) {
      if(      inflation->current.epoch==current_epoch                     ) inflation_state = &inflation->current;
      else if( inflation->has_prev && inflation->prev.epoch==current_epoch ) inflation_state = &inflation->prev;
    }
    if( FD_UNLIKELY( !inflation_state ) ) {
      FD_LOG_WARNING(( "slot %lu: no epoch inflation state for epoch %lu", bank_slot, current_epoch ));
      return -1;
    }
    max_reward      = inflation_state->max_possible_validator_reward;
    slots_per_epoch = inflation_state->slots_per_epoch;

    total_stake = fd_vote_stakes_total_stake( fd_bank_vote_stakes( bank ), reward_epoch );
    if( FD_UNLIKELY( !total_stake ) ) {
      FD_LOG_WARNING(( "slot %lu: no epoch stakes for reward epoch %lu", bank_slot, reward_epoch ));
      return -1;
    }

    reward_ts_ns = slot_timestamp( bank, reward_slot, footer_time_nanos );
    reward_kind  = vote_stakes_iter_kind_for_epoch( bank, reward_epoch );
    if( FD_UNLIKELY( !reward_kind ) ) {
      FD_LOG_WARNING(( "slot %lu: reward epoch %lu is not t-1 through t-5", bank_slot, reward_epoch ));
      return -1;
    }
  }

  /* finalization cert: root/votes/timestamp for the signers */

  if( has_final ) {
    if( footer->has_fast_final_cert ) {
      final_slot = footer->fast_final_cert.slot;
      fd_bls_set_copy( final_set, footer->fast_final_cert.signer_set );
    } else {
      final_slot = footer->final_cert.slot;
      fd_bls_set_union( final_set, footer->final_cert.signer_set, footer->notar_cert.signer_set );
    }
    final_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, final_slot, NULL );
    final_ts_ns = slot_timestamp( bank, final_slot, footer_time_nanos );
    final_kind  = vote_stakes_iter_kind_for_epoch( bank, final_epoch );
    if( FD_UNLIKELY( !final_kind ) ) {
      FD_LOG_WARNING(( "slot %lu: finalization epoch %lu is not t-1 through t-5", bank_slot, final_epoch ));
      return -1;
    }
  }

  /* Same epoch set: one walk, reward then final update, one store per
     signer (Agave update_accounts).  Else reward walk, then final. */

  uchar __attribute__((aligned(FD_VOTE_QUEUE_ALIGN))) q_mem[ FD_VOTE_QUEUE_FOOTPRINT ];
  fd_vote_queue_t * q = fd_vote_queue_init( q_mem );

  fd_pubkey_t const * leader_vote_pubkey = fd_epoch_leaders_get_vote( fd_bank_epoch_leaders_query( bank, current_epoch ), bank_slot );
  FD_TEST( leader_vote_pubkey );

  int   memo_kind   = vote_stakes_iter_kind_for_epoch( bank, current_epoch );
  ulong leader_rank = memo_rank( bank, memo_kind, leader_vote_pubkey );

  int fused = has_reward && final_kind==reward_kind;
  for( ulong pass=0UL; pass<2UL; pass++ ) {
    int rwd = !pass && has_reward;
    int fin = has_final && ( pass ? !fused : fused );
    if( !rwd && !fin ) continue;
    int iter_kind = rwd ? reward_kind : final_kind;

    int have_ranked_vote = 0;
    fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter ) ) {
      fd_vote_stakes_ele_t ele[1];
      fd_vote_stakes_iter_ele( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter, ele );
      if( FD_UNLIKELY( ele->rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL ) ) continue;
      FD_TEST( ele->rank<AG_VAT_MAX );
      have_ranked_vote = 1;
      ulong r      = (ulong)ele->rank;
      int   in_rwd = rwd && fd_bls_set_test( reward_set, r );
      int   in_fin = fin && fd_bls_set_test( final_set,  r );
      if( !in_rwd && !in_fin ) continue;

      static FD_TL fd_vote_state_versioned_t vs[1];
      fd_acc_t acc;

      /* Skip this node if the vote account cannot be deserialized
         https://github.com/anza-xyz/agave/blob/v4.3.0-beta.3/runtime/src/block_component_processor/vote_reward.rs#L378-L380 */
      if( FD_UNLIKELY( !vote_account_open( bank, accdb, &ele->pubkey, vs, &acc ) ) ) continue;

      if( in_rwd ) {
        /* per-slot, stake-fractional reward; split half validator, half
           (rounded up) leader */
        uint128 numerator   = (uint128)max_reward*(uint128)ele->stake;
        uint128 denominator = (uint128)slots_per_epoch*(uint128)total_stake;
        ulong   reward      = denominator ? (ulong)( numerator/denominator ) : 0UL;
        ulong   validator_reward = reward/2UL;

        /* Only accumulate the leader credits if the vote account could
           be successfully read.

           https://github.com/anza-xyz/agave/blob/v4.3.0-beta.3/runtime/src/block_component_processor/vote_reward.rs#L249 */
        leader_credits = fd_ulong_sat_add( leader_credits, reward-validator_reward );
        vote_update_apply( vs, &acc, &(vote_update_t){
          .update_votes    = 1, .vote_slot = reward_slot, .vote_ts_ns = reward_ts_ns,
          .credits         = validator_reward,
          .migration_epoch = migration_epoch,
          .current_epoch   = current_epoch,
        } );
      }
      if( in_fin ) {
        vote_update_apply( vs, &acc, &(vote_update_t){
          .update_root  = 1, .root_slot = final_slot,
          .update_votes = 1, .vote_slot = final_slot, .vote_ts_ns = final_ts_ns,
        } );
      }
      ulong m = iter_kind==memo_kind ? r : memo_rank( bank, memo_kind, &ele->pubkey );
      vote_account_store( bank, accdb, capture_ctx, &acc, vs, m!=ULONG_MAX ? cache->memo+m : NULL, q );
    }
    if( FD_UNLIKELY( !have_ranked_vote ) ) {
      if( rwd ) FD_LOG_WARNING(( "slot %lu: no ranked validators for reward slot %lu",    bank_slot, reward_slot ));
      else      FD_LOG_WARNING(( "slot %lu: no ranked validators for finalized slot %lu", bank_slot, final_slot  ));
      fd_vote_queue_fini( q );
      return -1;
    }
  }

  /* leader rewards */

  if( leader_credits ) {
    vote_update_t upd = {
      .credits         = leader_credits,
      .migration_epoch = migration_epoch,
      .current_epoch   = current_epoch,
    };
    vote_account_modify( bank, accdb, capture_ctx, leader_vote_pubkey, &upd, leader_rank!=ULONG_MAX ? cache->memo+leader_rank : NULL, q );
  }

  fd_lthash_add( fd_bank_lthash_locking_modify( bank ), fd_vote_queue_fini( q ) );
  fd_bank_lthash_end_locking_modify( bank );

  return 0;
}
