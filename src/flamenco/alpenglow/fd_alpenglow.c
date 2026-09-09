#include "fd_alpenglow.h"
#include "../rewards/fd_epoch_inflation_account.h"

#include "../runtime/fd_accdb_svm.h"
#include "../runtime/fd_pubkey_utils.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../choreo/votor/ag_vote_serde.h"

FD_STATIC_ASSERT( MAX_EPOCH_CREDITS_HISTORY==64UL, epoch_credits_bound );

static int
vote_stakes_iter_kind_for_epoch( ulong fork_id,
                                 ulong epoch ) {
  ulong fork_epoch = (ulong)fd_vote_stakes_fork_epoch( fork_id );
  if( FD_LIKELY( epoch==fork_epoch ) ) return FD_VOTE_STAKES_ITER_T_2;
  if( FD_LIKELY( fork_epoch && epoch==fork_epoch-1UL ) ) return FD_VOTE_STAKES_ITER_T_3;
  return 0;
}

/* Footer cert verification */
struct validator_set {
  ulong          epoch;
  ulong          validator_cnt;          /* 0 if not built */
  ulong          total_stake;
  blst_p1_affine bls_keys[ AG_VAT_MAX ]; /* indexed by rank */
  ulong          stakes  [ AG_VAT_MAX ]; /* indexed by rank */
};
typedef struct validator_set validator_set_t;

/* validator_set_for_slot makes set hold the validators of slot's epoch,
   rebuilding it only when the epoch differs from the one it holds.
   Returns 1 on success, 0 if the bank holds no ranked validators for
   the epoch. */

static int
validator_set_for_slot( validator_set_t * set,
                        fd_bank_t const * bank,
                        ulong             slot ) {
  ulong epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, slot, NULL );
  if( FD_LIKELY( set->validator_cnt && set->epoch==epoch ) ) return 1;

  ulong fork_id   = bank->vote_stakes_fork_id;
  int   iter_kind = vote_stakes_iter_kind_for_epoch( fork_id, epoch );
  if( FD_UNLIKELY( !iter_kind ) ) {
    FD_LOG_WARNING(( "slot %lu: cert epoch %lu is not t-2 or t-3", bank->f.slot, epoch ));
    return 0;
  }

  set->validator_cnt = 0UL;
  fd_vote_stakes_t const * vote_stakes = fd_bank_vote_stakes( bank );
  ulong cnt      = 0UL;
  ulong max_rank = 0UL;
  ulong total    = 0UL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, iter_kind, iter_mem );
       !fd_vote_stakes_iter_done( vote_stakes, fork_id, iter_kind, iter );
       fd_vote_stakes_iter_next( vote_stakes, fork_id, iter_kind, iter ) ) {
    fd_pubkey_t vote_key;
    ulong       stake;
    ushort      rank;
    uchar       bls_key[ FD_BLS_PUBKEY_UNCOMPRESSED_SZ ];
    fd_vote_stakes_iter_ele( vote_stakes, fork_id, iter_kind, iter, &vote_key, NULL, &stake, NULL, NULL, NULL, NULL, &rank, NULL, bls_key );
    if( FD_UNLIKELY( rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL ) ) continue;
    FD_TEST( rank<AG_VAT_MAX );

    if( FD_UNLIKELY( blst_p1_deserialize( set->bls_keys+rank, bls_key )!=BLST_SUCCESS ) ) {
      FD_LOG_WARNING(( "slot %lu: rank %u of epoch %lu has a malformed BLS key", bank->f.slot, rank, epoch ));
      return 0;
    }
    set->stakes[ rank ] = stake;
    max_rank = fd_ulong_max( max_rank, (ulong)rank );
    total   += stake;
    cnt++;
  }
  if( FD_UNLIKELY( !cnt || cnt!=max_rank+1UL ) ) {
    FD_LOG_WARNING(( "slot %lu: epoch %lu has %lu ranked validators, highest rank %lu", bank->f.slot, epoch, cnt, max_rank ));
    return 0;
  }
  set->epoch         = epoch;
  set->validator_cnt = cnt;
  set->total_stake   = total;
  return 1;
}

/* cert_verify checks one footer cert against its epoch's validator set.
   The aggregate signature verifies over the vote of vote_kind the
   signers would have signed, and if quorum_numer is nonzero the signers
   hold quorum_numer/5 of the epoch's stake.  i.e., for verifying
   reward certs, quorum_numer should be 0.

   Returns 1 if the cert verifies, 0 otherwise. */

static int
cert_verify( validator_set_t *              set,
             fd_bank_t const *              bank,
             fd_block_footer_cert_t const * cert,
             uint                           vote_kind,
             ulong                          quorum_numer,
             ushort                         shred_version ) {
  ulong bank_slot = bank->f.slot;
  ulong cert_slot = cert->slot;

  if( FD_UNLIKELY( !validator_set_for_slot( set, bank, cert_slot ) ) ) return 0;

  ulong last_rank = ag_bls_set_last( cert->signer_set ); /* ULONG_MAX when empty */
  if( FD_UNLIKELY( cert->nbits>set->validator_cnt || last_rank>=set->validator_cnt ) ) {
    FD_LOG_WARNING(( "slot %lu: footer cert for slot %lu names %u ranks (highest signer %lu) but its epoch has %lu validators",
                     bank_slot, cert_slot, cert->nbits, last_rank, set->validator_cnt ));
    return 0;
  }

  ag_bls_pub_t pub[1]; memset( pub, 0, sizeof(ag_bls_pub_t) );
  ulong        stake = 0UL;
  for( ulong rank=0UL; rank<=last_rank; rank++ ) {
    if( !ag_bls_set_test( cert->signer_set, rank ) ) continue;
    blst_p1_add_or_double_affine( pub, pub, set->bls_keys+rank );
    stake += set->stakes[ rank ];
  }
  if( FD_UNLIKELY( quorum_numer && (uint128)stake*(uint128)AG_QUORUM_THRESHOLD_DENOM<(uint128)set->total_stake*(uint128)quorum_numer ) ) {
    FD_LOG_WARNING(( "slot %lu: footer cert for slot %lu has %lu of %lu stake, below %lu/%lu",
                     bank_slot, cert_slot, stake, set->total_stake, quorum_numer, AG_QUORUM_THRESHOLD_DENOM ));
    return 0;
  }

  blst_p2_affine sig_affine[1];
  ag_bls_sig_t   sig[1];
  if( FD_UNLIKELY( blst_p2_uncompress( sig_affine, cert->sig )!=BLST_SUCCESS || !blst_p2_affine_in_g2( sig_affine ) ) ) {
    FD_LOG_WARNING(( "slot %lu: footer cert for slot %lu has a malformed signature", bank_slot, cert_slot ));
    return 0;
  }
  blst_p2_from_affine( sig, sig_affine );

  uchar payload[ AG_VOTE_SIGNING_SER_MAX ];
  ulong payload_sz = ag_vote_signing_ser( vote_kind, cert_slot, vote_kind==AG_VOTE_KIND_NOTAR ? cert->block_id.uc : NULL, shred_version, payload );
  if( FD_UNLIKELY( !ag_bls_agg_verify( pub, sig, payload, payload_sz ) ) ) {
    FD_LOG_WARNING(( "slot %lu: footer (is_reward %d) cert for slot %lu failed signature verification", bank_slot, quorum_numer ? 1 : 0, cert_slot ));
    return 0;
  }
  return 1;
}

int
fd_alpenglow_footer_verify( fd_bank_t const *         bank,
                            fd_block_footer_t const * footer,
                            ushort                    shred_version ) {
  int has_certs = footer->has_fast_final_cert | footer->has_final_cert | footer->has_skip_reward_cert | footer->has_notar_reward_cert;
  if( FD_LIKELY( !has_certs ) ) return 0;
  if( FD_UNLIKELY( !shred_version ) ) {
    FD_LOG_WARNING(( "slot %lu: footer carries certs but the shred version is not known yet; cannot verify them", bank->f.slot ));
    return -1;
  }

  /* ~200 KiB, kept across calls: consecutive blocks' certs almost
     always share an epoch */
  static FD_TL validator_set_t set[1];

  if( footer->has_fast_final_cert ) {
    if( FD_UNLIKELY( !cert_verify( set, bank, &footer->fast_final_cert,   AG_VOTE_KIND_NOTAR, AG_STRONG_QUORUM_THRESHOLD_NUMER, shred_version ) ) ) return -1;
  }
  if( footer->has_final_cert ) {
    if( FD_UNLIKELY( !cert_verify( set, bank, &footer->final_cert,        AG_VOTE_KIND_FINAL, AG_QUORUM_THRESHOLD_NUMER, shred_version ) ) ) return -1;
    if( FD_UNLIKELY( !cert_verify( set, bank, &footer->notar_cert,        AG_VOTE_KIND_NOTAR, AG_QUORUM_THRESHOLD_NUMER, shred_version ) ) ) return -1;
  }
  if( footer->has_skip_reward_cert ) {
    if( FD_UNLIKELY( !cert_verify( set, bank, &footer->skip_reward_cert,  AG_VOTE_KIND_SKIP,  0UL, shred_version ) ) ) return -1;
  }
  if( footer->has_notar_reward_cert ) {
    if( FD_UNLIKELY( !cert_verify( set, bank, &footer->notar_reward_cert, AG_VOTE_KIND_NOTAR, 0UL, shred_version ) ) ) return -1;
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
vote_account_read( fd_bank_t *                 bank,
                   fd_accdb_t *                accdb,
                   fd_pubkey_t const *         pk,
                   fd_vote_state_versioned_t * vs,
                   ulong *                     out_data_len,
                   fd_pubkey_t *               out_owner ) {
  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, pk->uc );
  if( FD_UNLIKELY( !acc.lamports || !fd_vsv_is_correct_size_owner_and_init( acc.owner, acc.data, acc.data_len ) ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return 0;
  }
  if( FD_UNLIKELY( fd_vsv_deserialize( &acc, vs ) ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return 0;
  }
  *out_data_len = acc.data_len;
  fd_memcpy( out_owner->uc, acc.owner, sizeof(fd_pubkey_t) );
  fd_accdb_unread_one( accdb, &acc );
  return 1;
}

static void
vote_account_write( fd_bank_t *                 bank,
                    fd_accdb_t *                accdb,
                    fd_capture_ctx_t *          capture_ctx,
                    fd_pubkey_t const *         pk,
                    fd_pubkey_t const *         owner,
                    ulong                       data_len,
                    fd_vote_state_versioned_t * vs,
                    vote_update_t const *       upd ) {
  static FD_TL uchar buf[ 8192UL ];

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
    FD_LOG_WARNING(( "slot %lu: vote account %s failed to serialize; skipping", bank->f.slot, pk_b58 ));
    return;
  }
  fd_accdb_svm_write( bank, accdb, capture_ctx, pk, owner, buf, data_len, 0UL, 0 );
}

static void
vote_account_modify( fd_bank_t *           bank,
                     fd_accdb_t *          accdb,
                     fd_capture_ctx_t *    capture_ctx,
                     fd_pubkey_t const *   pk,
                     vote_update_t const * upd ) {
  static FD_TL fd_vote_state_versioned_t vs[1];
  ulong       data_len;
  fd_pubkey_t owner;
  if( FD_UNLIKELY( !vote_account_read( bank, accdb, pk, vs, &data_len, &owner ) ) ) return;
  vote_account_write( bank, accdb, capture_ctx, pk, &owner, data_len, vs, upd );
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
  if( FD_UNLIKELY( !FD_FEATURE_ACTIVE_BANK( bank, alpenglow ) ) ) return ULONG_MAX;

  fd_pubkey_t genesis_cert_addr;
  fd_alpenglow_pda( "carlgration", &genesis_cert_addr );

  ulong    migration_slot = ULONG_MAX;
  fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, genesis_cert_addr.uc );
  if( FD_LIKELY( acc.lamports && acc.data_len>=8UL ) ) migration_slot = FD_LOAD( ulong, acc.data );
  fd_accdb_unread_one( accdb, &acc );
  return migration_slot;
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

int
fd_alpenglow_rewards_apply( fd_bank_t *               bank,
                            fd_accdb_t *              accdb,
                            fd_capture_ctx_t *        capture_ctx,
                            fd_block_footer_t const * footer ) {

  ulong bank_slot         = bank->f.slot;
  ulong footer_time_nanos = footer->block_producer_time_nanos;
  ulong current_epoch     = fd_slot_to_epoch( &bank->f.epoch_schedule, bank_slot, NULL );
  ulong migration_epoch   = ULONG_MAX;
  ulong leader_credits    = 0UL;

  /* credits for the attested voters of the reward slot */

  if( footer->has_skip_reward_cert || footer->has_notar_reward_cert ) {
    ag_bls_set_t reward_set[ ag_bls_set_word_cnt ];
    ag_bls_set_null( reward_set );
    ulong skip_slot = ULONG_MAX, notar_slot = ULONG_MAX;
    if( footer->has_skip_reward_cert ) {
      skip_slot = footer->skip_reward_cert.slot;
      ag_bls_set_union( reward_set, reward_set, footer->skip_reward_cert.signer_set );
    }
    if( footer->has_notar_reward_cert ) {
      notar_slot = footer->notar_reward_cert.slot;
      ag_bls_set_union( reward_set, reward_set, footer->notar_reward_cert.signer_set );
    }
    if( FD_UNLIKELY( skip_slot!=ULONG_MAX && notar_slot!=ULONG_MAX && skip_slot!=notar_slot ) ) {
      FD_LOG_WARNING(( "slot %lu: reward cert slots differ: skip %lu, notar %lu", bank_slot, skip_slot, notar_slot ));
      return -1;
    }
    ulong reward_slot = fd_ulong_min( skip_slot, notar_slot );

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
    ulong max_reward      = inflation_state->max_possible_validator_reward;
    ulong slots_per_epoch = inflation_state->slots_per_epoch;

    ulong total_stake = fd_vote_stakes_total_stake( fd_bank_vote_stakes( bank ), reward_epoch );
    if( FD_UNLIKELY( !total_stake ) ) {
      FD_LOG_WARNING(( "slot %lu: no epoch stakes for reward epoch %lu", bank_slot, reward_epoch ));
      return -1;
    }

    long ts_ns = slot_timestamp( bank, reward_slot, footer_time_nanos );
    int have_ranked_vote = 0;
    fd_vote_stakes_t const * vote_stakes = fd_bank_vote_stakes( bank );
    int iter_kind = vote_stakes_iter_kind_for_epoch( bank->vote_stakes_fork_id, reward_epoch );
    if( FD_UNLIKELY( !iter_kind ) ) {
      FD_LOG_WARNING(( "slot %lu: reward epoch %lu is not t-2 or t-3", bank_slot, reward_epoch ));
      return -1;
    }
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter ) ) {
      fd_pubkey_t vote_key;
      ulong       stake;
      ushort      rank;
      fd_vote_stakes_iter_ele( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter,
                               &vote_key, NULL, &stake, NULL, NULL, NULL, NULL, &rank, NULL, NULL );
      if( FD_UNLIKELY( rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL ) ) continue;
      FD_TEST( rank<AG_VAT_MAX );
      have_ranked_vote = 1;
      ulong r = (ulong)rank;
      if( !ag_bls_set_test( reward_set, r ) ) continue;
      /* per-slot, stake-fractional reward; split half validator, half
         (rounded up) leader */
      uint128 numerator   = (uint128)max_reward*(uint128)stake;
      uint128 denominator = (uint128)slots_per_epoch*(uint128)total_stake;
      ulong   reward      = denominator ? (ulong)( numerator/denominator ) : 0UL;
      ulong   validator_reward = reward/2UL;

      vote_update_t upd = {
        .update_votes    = 1, .vote_slot = reward_slot, .vote_ts_ns = ts_ns,
        .credits         = validator_reward,
        .migration_epoch = migration_epoch,
        .current_epoch   = current_epoch,
      };
      static FD_TL fd_vote_state_versioned_t vs[1];
      ulong       data_len;
      fd_pubkey_t owner;

      /* Skip this node if the vote account cannot be deserialized
         https://github.com/anza-xyz/agave/blob/v4.3.0-beta.3/runtime/src/block_component_processor/vote_reward.rs#L378-L380 */
      if( FD_UNLIKELY( !vote_account_read( bank, accdb, &vote_key, vs, &data_len, &owner ) ) ) continue;

      /* Only accumulate the leader credits if the vote account could
         be successfully read.

         https://github.com/anza-xyz/agave/blob/v4.3.0-beta.3/runtime/src/block_component_processor/vote_reward.rs#L249 */
      leader_credits = fd_ulong_sat_add( leader_credits, reward-validator_reward );
      vote_account_write( bank, accdb, capture_ctx, &vote_key, &owner, data_len, vs, &upd );
    }
    if( FD_UNLIKELY( !have_ranked_vote ) ) {
      FD_LOG_WARNING(( "slot %lu: no ranked validators for reward slot %lu", bank_slot, reward_slot ));
      return -1;
    }
  }

  /* finalization cert: root/votes/timestamp for the signers */

  if( footer->has_fast_final_cert || footer->has_final_cert ) {
    ulong        final_slot;
    ag_bls_set_t final_set[ ag_bls_set_word_cnt ];
    if( footer->has_fast_final_cert ) {
      final_slot = footer->fast_final_cert.slot;
      ag_bls_set_copy( final_set, footer->fast_final_cert.signer_set );
    } else {
      final_slot = footer->final_cert.slot;
      ag_bls_set_union( final_set, footer->final_cert.signer_set, footer->notar_cert.signer_set );
    }

    ulong final_epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, final_slot, NULL );

    long ts_ns = slot_timestamp( bank, final_slot, footer_time_nanos );
    int have_ranked_vote = 0;
    fd_vote_stakes_t const * vote_stakes = fd_bank_vote_stakes( bank );
    int iter_kind = vote_stakes_iter_kind_for_epoch( bank->vote_stakes_fork_id, final_epoch );
    if( FD_UNLIKELY( !iter_kind ) ) {
      FD_LOG_WARNING(( "slot %lu: finalization epoch %lu is not t-2 or t-3", bank_slot, final_epoch ));
      return -1;
    }
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter ) ) {
      fd_pubkey_t vote_key;
      ushort      rank;
      fd_vote_stakes_iter_ele( vote_stakes, bank->vote_stakes_fork_id, iter_kind, iter,
                               &vote_key, NULL, NULL, NULL, NULL, NULL, NULL, &rank, NULL, NULL );
      if( FD_UNLIKELY( rank==FD_VOTE_STAKES_ALPENGLOW_RANK_NULL ) ) continue;
      FD_TEST( rank<AG_VAT_MAX );
      have_ranked_vote = 1;
      ulong r = (ulong)rank;
      if( !ag_bls_set_test( final_set, r ) ) continue;
      vote_update_t upd = {
        .update_root  = 1, .root_slot = final_slot,
        .update_votes = 1, .vote_slot = final_slot, .vote_ts_ns = ts_ns,
      };
      vote_account_modify( bank, accdb, capture_ctx, &vote_key, &upd );
    }
    if( FD_UNLIKELY( !have_ranked_vote ) ) {
      FD_LOG_WARNING(( "slot %lu: no ranked validators for finalized slot %lu", bank_slot, final_slot ));
      return -1;
    }
  }

  /* leader rewards */

  if( leader_credits ) {
    fd_pubkey_t const * leader_vote_pubkey = fd_epoch_leaders_get_vote( fd_bank_epoch_leaders_query( bank, current_epoch ), bank_slot );
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
