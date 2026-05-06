ENCODE_FN {

  PREP

  switch( enc->state ) {

  case STATE_HEADER:
    PUSH_VAL( ulong, enc->slot_cnt );
    enc->slot_idx  = 0UL;
    enc->group_idx = 0UL;
    enc->txn_idx   = 0UL;
    enc->state = enc->slot_cnt ? STATE_SLOT : STATE_DONE;
    break;

  case STATE_SLOT: {
    ulong slot = enc->slot_delta[ enc->slot_idx ];
    PUSH_VAL( ulong, slot );
    PUSH_VAL( uchar, 1    );
    PUSH_VAL( ulong, slot==enc->slot ? enc->group_cnt : 0UL );
    if( FD_LIKELY( slot==enc->slot && enc->group_cnt ) ) {
      enc->group_idx = 0UL;
      enc->txn_idx   = 0UL;
      enc->state     = STATE_BLOCKHASH;
    } else {
      enc->slot_idx++;
      enc->state = enc->slot_idx==enc->slot_cnt ? STATE_DONE : STATE_SLOT;
    }
    break;
  }

  case STATE_BLOCKHASH: {
    fd_txncache_writer_group_t const * group = &enc->group[ enc->group_idx ];
    fd_hash_t blockhash;
    memcpy( blockhash.uc, group->blockhash, 32UL );
    PUSH_VAL( fd_hash_t, blockhash              );
    PUSH_VAL( ulong,     group->txnhash_offset  );
    PUSH_VAL( ulong,     group->txn_cnt         );
    enc->txn_idx = 0UL;
    enc->state = group->txn_cnt ? STATE_TXNS : STATE_BLOCKHASH;
    if( FD_UNLIKELY( !group->txn_cnt ) ) {
      enc->group_idx++;
      if( FD_UNLIKELY( enc->group_idx==enc->group_cnt ) ) {
        enc->slot_idx++;
        enc->state = enc->slot_idx==enc->slot_cnt ? STATE_DONE : STATE_SLOT;
      }
    }
    break;
  }

  case STATE_TXNS: {
    fd_txncache_writer_group_t const * group = &enc->group[ enc->group_idx ];
    if( FD_UNLIKELY( !enc->txn_iter_active ) ) {
      fd_txncache_iter_init( enc->tc, enc->txn_iter, group->blockhash_fork_id );
      enc->txn_iter_active = 1;
    }
    while( !fd_txncache_iter_done( enc->txn_iter ) ) {
      if( FD_UNLIKELY( !CAN_PUSH( sizeof(fd_txnhash_20_t)+sizeof(uint) ) ) ) {
        return RET_EXPR;
      }
      fd_txncache_iter_ele_t const * ele = fd_txncache_iter_ele( enc->txn_iter );
      fd_txnhash_20_t txnhash;
      memcpy( txnhash.b, ele->txnhash, 20UL );
      PUSH_VAL( fd_txnhash_20_t, txnhash );
      PUSH_VAL( uint,            0U      );
      enc->txn_idx++;
      fd_txncache_iter_next( enc->txn_iter );
    }
    fd_txncache_iter_fini( enc->txn_iter );
    enc->txn_iter_active = 0;
    if( FD_UNLIKELY( enc->txn_idx!=group->txn_cnt ) ) FD_LOG_ERR(( "txncache writer emitted %lu txns, expected %lu", enc->txn_idx, group->txn_cnt ));
    enc->group_idx++;
    if( FD_UNLIKELY( enc->group_idx==enc->group_cnt ) ) {
      enc->slot_idx++;
      enc->state = enc->slot_idx==enc->slot_cnt ? STATE_DONE : STATE_SLOT;
    } else {
      enc->state = STATE_BLOCKHASH;
    }
    break;
  }

  case STATE_DONE:
    return 0UL;

  default:
    FD_LOG_ERR(( "invalid encoder state %u", enc->state ));
  }

  return RET_EXPR;
}

#undef PREP
#undef ENCODE_FN
#undef PUSH_VAL
#undef CAN_PUSH
#undef RET_EXPR
