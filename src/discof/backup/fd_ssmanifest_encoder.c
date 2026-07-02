/* Serialize a chunk of values.
   Each call may only produce up to FD_SSMANIFEST_BUF_MIN bytes worth of
   serialized data.  Therefore, we split the serializer into multiple
   states. */

ENCODE_FN {
  fd_bank_t const * bank = enc->bank;

  PREP

  switch( enc->state ) {
  case STATE_BLOCKHASH_QUEUE: {
    fd_blockhashes_t const *    bhq = &bank->f.block_hash_queue;
    fd_blockhash_info_t const * deq = bhq->d.deque;
    ulong total    = fd_blockhash_deq_cnt( deq );
    ulong to_write = fd_ulong_min( total, FD_BLOCKHASHES_MAX );
    ulong to_skip  = total - to_write;
    PUSH_VAL( ulong, to_write-1UL ); /* last hash index */
    fd_hash_t const * last_hash = fd_blockhashes_peek_last_hash( bhq );
    PUSH_VAL( uchar, !!last_hash );
    if( last_hash ) PUSH_VAL( fd_hash_t, *last_hash );

    PUSH_VAL( ulong, to_write );
    for( ulong i=0UL; i<to_write; i++ ) {
      fd_blockhash_info_t const * ele = fd_blockhash_deq_peek_index_const( deq, to_skip+i );
      PUSH_VAL( fd_hash_t, ele->hash );
      PUSH_VAL( ulong,     ele->lamports_per_signature );
      PUSH_VAL( ulong,     i );
      PUSH_VAL( ulong,     0UL ); /* timestamp, ignored */
    }
    PUSH_VAL( ulong, FD_BLOCKHASHES_MAX-1UL ); /* max_age */
    enc->state = STATE_HASHES;
    break;
  }
  case STATE_HASHES: {
    PUSH_VAL( ulong,     0UL ); /* ancestors */
    PUSH_VAL( fd_hash_t, bank->f.bank_hash      );
    PUSH_VAL( fd_hash_t, bank->f.prev_bank_hash );
    PUSH_VAL( ulong,     bank->f.parent_slot    );
    enc->state = STATE_HARD_FORKS;
    break;
  }
  case STATE_HARD_FORKS: {
    PUSH_VAL( ulong, bank->f.hard_fork_cnt );
    for( ulong i=0UL; i<bank->f.hard_fork_cnt; i++ ) {
      PUSH_VAL( ulong, bank->f.hard_forks[ i ].slot );
      PUSH_VAL( ulong, bank->f.hard_forks[ i ].cnt  );
    }
    enc->state = STATE_COUNTERS;
    break;
  }
  case STATE_COUNTERS: {
    PUSH_VAL( ulong,  bank->f.txn_count             );
    PUSH_VAL( ulong,  bank->f.tick_height           );
    PUSH_VAL( ulong,  bank->f.signature_count       );
    PUSH_VAL( ulong,  bank->f.capitalization        );
    PUSH_VAL( ulong,  bank->f.max_tick_height       );
    PUSH_VAL( uchar,  1                             );
    PUSH_VAL( ulong,  bank->f.hashes_per_tick       );
    PUSH_VAL( ulong,  bank->f.ticks_per_slot        );
    PUSH_VAL( fd_w_u128_t, bank->f.ns_per_slot      );
    PUSH_VAL( ulong,  bank->f.genesis_creation_time );
    PUSH_VAL( double, bank->f.slots_per_year        );
    PUSH_VAL( ulong,  0UL ); /* accounts_data_len, unused */
    PUSH_VAL( ulong,  bank->f.slot                  );
    PUSH_VAL( ulong,  bank->f.epoch                 );
    PUSH_VAL( ulong,  bank->f.block_height          );
    PUSH_VAL( fd_pubkey_t, (fd_pubkey_t){0} ); /* leader_id, unused */
    PUSH_VAL( ulong, 0UL ); /* unused_collector_fees */
    PUSH_VAL( ulong, 0UL ); /* unused_fee_calculator */

    fd_fee_rate_governor_t const * frg = &bank->f.fee_rate_governor;
    PUSH_VAL( ulong, frg->target_lamports_per_signature );
    PUSH_VAL( ulong, frg->target_signatures_per_slot    );
    PUSH_VAL( ulong, frg->min_lamports_per_signature    );
    PUSH_VAL( ulong, frg->max_lamports_per_signature    );
    PUSH_VAL( uchar, frg->burn_percent                  );
    PUSH_VAL( ulong, 0UL );
    PUSH_VAL( ulong, bank->f.epoch );

    fd_epoch_schedule_t const * es = &bank->f.epoch_schedule;
    fd_rent_t const * rent = &bank->f.rent;
    PUSH_VAL( ulong,  es->slots_per_epoch             );
    PUSH_VAL( ulong,  es->leader_schedule_slot_offset );
    PUSH_VAL( uchar,  es->warmup                      );
    PUSH_VAL( ulong,  es->first_normal_epoch          );
    PUSH_VAL( ulong,  es->first_normal_slot           );
    PUSH_VAL( double, bank->f.slots_per_year          );
    PUSH_VAL( ulong,  rent->lamports_per_uint8_year   );
    PUSH_VAL( double, rent->exemption_threshold       );
    PUSH_VAL( uchar,  rent->burn_percent              );
    PUSH_VAL( ulong,  es->slots_per_epoch             );
    PUSH_VAL( ulong,  es->leader_schedule_slot_offset );
    PUSH_VAL( uchar,  es->warmup                      );
    PUSH_VAL( ulong,  es->first_normal_epoch          );
    PUSH_VAL( ulong,  es->first_normal_slot           );

    fd_inflation_t const * inf = &bank->f.inflation;
    PUSH_VAL( double, inf->initial        );
    PUSH_VAL( double, inf->terminal       );
    PUSH_VAL( double, inf->taper          );
    PUSH_VAL( double, inf->foundation     );
    PUSH_VAL( double, inf->foundation_term );
    PUSH_VAL( double, inf->unused          );

    enc->state = STATE_VOTE_ACCOUNTS;
    break;
  }
  case STATE_VOTE_ACCOUNTS: {
    PUSH_VAL( ulong, 0UL ); /* zero vote_accounts */
    PUSH_VAL( ulong, 0UL ); /* zero stake delegations */
    PUSH_VAL( ulong, 0UL ); /* unused */
    PUSH_VAL( ulong, bank->f.epoch );
    enc->state = STATE_STAKE_HISTORY;
    break;
  }
  case STATE_STAKE_DELEGATION: { FD_LOG_ERR(( "TODO")); }
  case STATE_STAKE_EPOCH: { FD_LOG_ERR(( "TODO")); }
  case STATE_STAKE_HISTORY: {
    PUSH_VAL( ulong, 0UL ); /* zero stake history entries */
    enc->state = STATE_BANK_TRAILER;
    break;
  }
  case STATE_BANK_TRAILER: {
    PUSH_VAL( ulong, 0UL ); /* unused_accounts.unused1 */
    PUSH_VAL( ulong, 0UL ); /* unused_accounts.unused2 */
    PUSH_VAL( ulong, 0UL ); /* unused_accounts.unused3 */
    PUSH_VAL( ulong, 0UL ); /* unused_epoch_stakes */
    PUSH_VAL( uchar, 0   ); /* is_delta */
    PUSH_VAL( ulong, 0UL ); /* zero account_storage_entries */
    enc->state = STATE_BANK_HASH_INFO;
    break;
  }
  case STATE_ACCOUNT_STORAGE_ENTRY: { FD_LOG_ERR(( "TODO")); }
  case STATE_BANK_HASH_INFO: {
    /* AccountsDbFields */
    PUSH_VAL( ulong, 0UL          ); /* write_version, unused */
    PUSH_VAL( ulong, bank->f.slot ); /* slot */
    PUSH_VAL( fd_hash_t, (fd_hash_t){0} ); /* unused_accounts_delta_hash */
    PUSH_VAL( fd_hash_t, (fd_hash_t){0} ); /* unused_accounts_hash */
    PUSH_VAL( ulong, 0UL ); /* num_updated_accounts, unused */
    PUSH_VAL( ulong, 0UL ); /* num_removed_accounts, unused */
    PUSH_VAL( ulong, 0UL ); /* num_lamports_stored, unused */
    PUSH_VAL( ulong, 0UL ); /* total_data_len, unused */
    PUSH_VAL( ulong, 0UL ); /* num_executable_accounts, unused */
    PUSH_VAL( ulong, 0UL ); /* historical_roots, unused */
    PUSH_VAL( ulong, 0UL ); /* historical_roots_with_hash, unused */
    /* ExtraFieldsToSerialize */
    PUSH_VAL( ulong, bank->f.rbh_lamports_per_sig );
    PUSH_VAL( uchar, 0 ); /* unused_incremental_snapshot_persistence */
    PUSH_VAL( uchar, 0 ); /* unused_epoch_accounts_hash */

    ulong epoch = bank->f.epoch;
    ulong epoch_cnt = (epoch > 0UL) ? 3UL : 2UL;
    PUSH_VAL( ulong, epoch_cnt );
    enc->epoch_cnt = (uchar)epoch_cnt;
    enc->epoch_idx = 0;
    enc->state = STATE_EPOCH_STAKES;
    break;
  }
  case STATE_EPOCH_STAKES: {
    ulong epoch = bank->f.epoch;
    ulong epoch_stakes_base = (epoch > 0UL) ? (epoch - 1UL) : 0UL;
    ulong epoch_key = epoch_stakes_base + (ulong)enc->epoch_idx;

    /* entry_type: 0=T-3 commission, 1=T-2 stakes, 2=T-1 stakes+credits */
    uint entry_type = (epoch > 0UL) ? enc->epoch_idx : (uint)(enc->epoch_idx + 1U);

    uint vote_cnt;
    if( entry_type==2U ) {
      vote_cnt = (uint)*fd_bank_epoch_credits_len( enc->bank );
    } else if( entry_type==1U ) {
      vote_cnt = (uint)*fd_bank_epoch_credits_len( enc->bank );
    } else {
      vote_cnt = (uint)*fd_bank_snapshot_commission_t_3_len( enc->bank );
    }
    enc->vote_cnt    = vote_cnt;
    enc->vote_idx    = 0;
    enc->total_stake = 0UL;

    PUSH_VAL( ulong, epoch_key );
    PUSH_VAL( uint,  0U ); /* variant = 0 (VersionedEpochStakes::Current) */
    PUSH_VAL( ulong, (ulong)vote_cnt );

    enc->state = (vote_cnt > 0U) ? STATE_EPOCH_STAKES_STAKES : STATE_EPOCH_STAKES_EPOCH;
    break;
  }
  case STATE_EPOCH_STAKES_STAKES: {
    ulong epoch = bank->f.epoch;
    uint entry_type = (epoch > 0UL) ? enc->epoch_idx : (uint)(enc->epoch_idx + 1U);

    fd_pubkey_t pubkey       = {0};
    ulong       stake        = 0UL;
    fd_pubkey_t node_account = {0};
    ushort      commission   = 0;
    ulong       ec_cnt       = 0UL;
    fd_epoch_credits_t const * ec = NULL;

    fd_vote_stakes_t * vs       = fd_bank_vote_stakes( bank );
    ushort             fork_idx = fd_vote_stakes_get_root_idx( vs );

    if( entry_type==2U ) {
      ec     = &fd_bank_epoch_credits( enc->bank )[ enc->vote_idx ];
      ec_cnt = ec->cnt;
      fd_memcpy( &pubkey, ec->pubkey, 32UL );
      fd_vote_stakes_query_t_1( vs, fork_idx, &pubkey, &stake, &node_account, &commission );
    } else if( entry_type==1U ) {
      fd_epoch_credits_t const * ec_src = &fd_bank_epoch_credits( enc->bank )[ enc->vote_idx ];
      fd_memcpy( &pubkey, ec_src->pubkey, 32UL );
      fd_vote_stakes_query_t_2( vs, fork_idx, &pubkey, &stake, &node_account, &commission );
    } else {
      fd_stashed_commission_t const * sc = &fd_bank_snapshot_commission_t_3( enc->bank )[ enc->vote_idx ];
      fd_memcpy( &pubkey, sc->pubkey, 32UL );
      commission = sc->commission;
    }

    enc->total_stake += stake;
    ulong data_length = 186UL + 24UL * ec_cnt;

    /* Vote account key + stake */
    PUSH_VAL( fd_pubkey_t, pubkey );
    PUSH_VAL( ulong,       stake  );

    /* AccountSharedData: lamports, data_length */
    PUSH_VAL( ulong, 0UL         );
    PUSH_VAL( ulong, data_length );

    /* VoteStateV4 */
    PUSH_VAL( uint,       3U           ); /* variant = V4 */
    PUSH_VAL( fd_pubkey_t, node_account ); /* node_pubkey */
    PUSH_VAL( fd_pubkey_t, (fd_pubkey_t){0} ); /* authorized_withdrawer */
    PUSH_VAL( fd_pubkey_t, (fd_pubkey_t){0} ); /* inflation_rewards_collector */
    PUSH_VAL( fd_pubkey_t, (fd_pubkey_t){0} ); /* block_revenue_collector */
    PUSH_VAL( ushort, (ushort)((uint)commission * 100U) ); /* inflation_rewards_commission_bps */
    PUSH_VAL( ushort, (ushort)0 ); /* block_revenue_commission_bps */
    PUSH_VAL( ulong,  0UL      ); /* pending_delegator_rewards */
    PUSH_VAL( uchar,  0        ); /* bls_pubkey_compressed = None */
    PUSH_VAL( ulong,  0UL      ); /* votes_length = 0 */
    PUSH_VAL( uchar,  0        ); /* root_slot = None */
    PUSH_VAL( ulong,  0UL      ); /* authorized_voters_length = 0 */

    /* Epoch credits */
    PUSH_VAL( ulong, ec_cnt );
    for( ulong j=0UL; j<ec_cnt; j++ ) {
      PUSH_VAL( ulong, (ulong)ec->epoch[j] );
      PUSH_VAL( ulong, ec->base_credits + (ulong)ec->credits_delta[j] );
      PUSH_VAL( ulong, ec->base_credits + (ulong)ec->prev_credits_delta[j] );
    }

    PUSH_VAL( ulong, 0UL ); /* last_timestamp_slot */
    PUSH_VAL( ulong, 0UL ); /* last_timestamp_timestamp */

    /* AccountSharedData trailer */
    PUSH_VAL( fd_pubkey_t, fd_solana_vote_program_id ); /* owner */
    PUSH_VAL( uchar,       1                         ); /* executable */
    PUSH_VAL( ulong,       0UL                       ); /* rent_epoch */

    enc->vote_idx++;
    if( enc->vote_idx >= enc->vote_cnt ) enc->state = STATE_EPOCH_STAKES_EPOCH;
    break;
  }
  case STATE_EPOCH_STAKES_EPOCH: {
    ulong epoch = bank->f.epoch;
    ulong epoch_stakes_base = (epoch > 0UL) ? (epoch - 1UL) : 0UL;
    ulong epoch_key = epoch_stakes_base + (ulong)enc->epoch_idx;

    PUSH_VAL( ulong, 0UL       ); /* stake_delegations_length = 0 */
    PUSH_VAL( ulong, 0UL       ); /* unused */
    PUSH_VAL( ulong, epoch_key ); /* epoch */
    PUSH_VAL( ulong, 0UL       ); /* stake_history_length = 0 */
    enc->state = STATE_EPOCH_TOTAL_STAKE;
    break;
  }
  case STATE_EPOCH_STAKE_HISTORY: { __builtin_unreachable(); }
  case STATE_EPOCH_TOTAL_STAKE: {
    uint entry_type = (bank->f.epoch > 0UL) ? enc->epoch_idx : (uint)(enc->epoch_idx + 1U);
    ulong total_stake = (entry_type==2U) ? bank->f.total_epoch_stake : enc->total_stake;
    PUSH_VAL( ulong, total_stake );
    enc->state = STATE_NODE_VOTE_ACCOUNTS;
    break;
  }
  case STATE_NODE_VOTE_ACCOUNTS: {
    PUSH_VAL( ulong, 0UL ); /* node_id_to_vote_accounts_length = 0 */
    enc->state = STATE_AUTH_VOTER;
    break;
  }
  case STATE_AUTH_VOTER: {
    PUSH_VAL( ulong, 0UL ); /* epoch_authorized_voters_length = 0 */
    enc->epoch_idx++;
    enc->state = (enc->epoch_idx < enc->epoch_cnt) ? STATE_EPOCH_STAKES : STATE_LTHASH;
    break;
  }
  case STATE_LTHASH: {
    PUSH_VAL( uchar, 1 );
    PUSH_VAL( fd_lthash_value_t, bank->f.lthash );
    enc->state = STATE_DONE;
    break;
  }
  case STATE_DONE:
    return 0UL;
  default:
    FD_LOG_CRIT(( "invalid state reached (%u)", enc->state ));
  }

  return RET_EXPR;
}

#undef PREP
#undef ENCODE_FN
#undef PUSH_VAL
#undef RET_EXPR
