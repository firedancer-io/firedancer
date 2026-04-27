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
    PUSH_VAL( ulong, fd_blockhash_deq_cnt( deq )-1UL ); /* last hash index, wraparound fine */
    fd_hash_t const * last_hash = fd_blockhashes_peek_last_hash( bhq );
    PUSH_VAL( uchar, !!last_hash );
    if( last_hash ) PUSH_VAL( fd_hash_t, *last_hash );

    PUSH_VAL( ulong, fd_blockhash_deq_cnt( deq ) );
    ulong cnt = 0UL;
    for( fd_blockhash_deq_iter_t iter=fd_blockhash_deq_iter_init( deq );
         !fd_blockhash_deq_iter_done( deq, iter );
         iter=fd_blockhash_deq_iter_next( deq, iter ) ) {
      fd_blockhash_info_t const * ele = fd_blockhash_deq_iter_ele_const( deq, iter );
      PUSH_VAL( fd_hash_t, ele->hash );
      PUSH_VAL( ulong,     ele->lamports_per_signature );
      PUSH_VAL( ulong,     cnt );
      PUSH_VAL( ulong,     0UL ); /* timestamp, ignored */
      cnt++;
    }
    PUSH_VAL( ulong, 300UL ); /* max_age */
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
    /* FIXME support hard forks */
    PUSH_VAL( ulong, 0UL );
    enc->state = STATE_COUNTERS;
    break;
  }
  case STATE_COUNTERS: {
    PUSH_VAL( ulong,  bank->f.transaction_count     );
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
    PUSH_VAL( ulong, 0UL ); /* FIXME lamports_per_signature */
    PUSH_VAL( uchar, 0   ); /* unused_incremental_snapshot_persistence */
    PUSH_VAL( uchar, 0   ); /* unused_epoch_accounts_hash */
    PUSH_VAL( ulong, 0UL ); /* FIXME versioned_epoch_stakes */
    enc->state = STATE_LTHASH;
    break;
  }
  case STATE_EPOCH_STAKES: { FD_LOG_ERR(( "TODO")); }
  case STATE_EPOCH_STAKES_STAKES: { FD_LOG_ERR(( "TODO")); }
  case STATE_EPOCH_STAKES_EPOCH: { FD_LOG_ERR(( "TODO")); }
  case STATE_EPOCH_STAKE_HISTORY: { FD_LOG_ERR(( "TODO")); }
  case STATE_EPOCH_TOTAL_STAKE: { FD_LOG_ERR(( "TODO")); }
  case STATE_NODE_VOTE_ACCOUNTS: { FD_LOG_ERR(( "TODO")); }
  case STATE_AUTH_VOTER: { FD_LOG_ERR(( "TODO")); }
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
