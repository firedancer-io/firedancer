/* Serialize status_cache (Vec<SlotDelta>) for a Solana snapshot.
   Included twice: once for size estimation, once for actual encoding.
   See fd_ssmanifest_encoder.c for the pattern. */

ENCODE_FN {

  PREP

  fd_txncache_writer_tc_t const * tc = (fd_txncache_writer_tc_t const *)enc->tc;

  switch( enc->state ) {

  case STATE_HEADER: {
    ulong root_cnt = 0UL;
    for( ulong it = root_slist_iter_init( tc->shmem->root_ll, tc->blockcache_shmem_pool );
         !root_slist_iter_done( it, tc->shmem->root_ll, tc->blockcache_shmem_pool );
         it = root_slist_iter_next( it, tc->shmem->root_ll, tc->blockcache_shmem_pool ) ) {
      root_cnt++;
    }
    PUSH_VAL( ulong, 1UL                ); /* slot_deltas_len = 1 */
    PUSH_VAL( ulong, enc->slot          ); /* slot                */
    PUSH_VAL( uchar, 1                  ); /* is_root = true      */
    PUSH_VAL( ulong, root_cnt           ); /* status_len         */
    enc->root_iter = root_slist_iter_init( tc->shmem->root_ll, tc->blockcache_shmem_pool );
    if( root_slist_iter_done( enc->root_iter, tc->shmem->root_ll, tc->blockcache_shmem_pool ) ) {
      enc->state = STATE_DONE;
    } else {
      enc->state = STATE_BLOCKHASH;
    }
    break;
  }

  case STATE_BLOCKHASH: {
    ulong bc_idx = root_slist_iter_idx( enc->root_iter, tc->shmem->root_ll, tc->blockcache_shmem_pool );
    fd_txncache_blockcache_shmem_t const * bc_shmem = &tc->blockcache_shmem_pool[ bc_idx ];

    PUSH_VAL( fd_hash_t, bc_shmem->blockhash      );
    PUSH_VAL( ulong,     bc_shmem->txnhash_offset  );

    ulong txn_cnt = txncache_count_txns( tc, enc->snapshot_root_idx, bc_idx );
    PUSH_VAL( ulong, txn_cnt );

    if( txn_cnt ) {
      fd_txncache_writer_blockcache_t const * bc = &tc->blockcache_pool[ bc_idx ];
      enc->page_idx    = 0UL;
      enc->txn_idx     = 0UL;
      enc->txns_in_page = FD_TXNCACHE_TXNS_PER_PAGE - (ulong)tc->txnpages[ bc->pages[ 0 ] ].free;
      enc->state = STATE_TXNS;
    } else {
      enc->root_iter = root_slist_iter_next( enc->root_iter, tc->shmem->root_ll, tc->blockcache_shmem_pool );
      if( root_slist_iter_done( enc->root_iter, tc->shmem->root_ll, tc->blockcache_shmem_pool ) ) {
        enc->state = STATE_DONE;
      }
    }
    break;
  }

  case STATE_TXNS: {
    ulong bc_idx = root_slist_iter_idx( enc->root_iter, tc->shmem->root_ll, tc->blockcache_shmem_pool );
    fd_txncache_blockcache_shmem_t const * bc_shmem = &tc->blockcache_shmem_pool[ bc_idx ];
    fd_txncache_writer_blockcache_t const * bc      = &tc->blockcache_pool[ bc_idx ];

    while( enc->page_idx < (ulong)bc_shmem->pages_cnt ) {
      fd_txncache_txnpage_t const * page = &tc->txnpages[ bc->pages[ enc->page_idx ] ];
      while( enc->txn_idx < enc->txns_in_page ) {
        fd_txncache_single_txn_t const * txn = page->txns[ enc->txn_idx ];
        if( FD_UNLIKELY( !txncache_txn_on_snapshot_root( tc, enc->snapshot_root_idx, txn ) ) ) {
          enc->txn_idx++;
          continue;
        }
        fd_txnhash_20_t h;
        __builtin_memcpy( h.b, txn->txnhash, 20UL );
        PUSH_VAL( fd_txnhash_20_t, h  );
        PUSH_VAL( uint,            0U ); /* result = Ok */
        enc->txn_idx++;
      }
      enc->page_idx++;
      enc->txn_idx = 0UL;
      if( enc->page_idx < (ulong)bc_shmem->pages_cnt ) {
        enc->txns_in_page = FD_TXNCACHE_TXNS_PER_PAGE - (ulong)tc->txnpages[ bc->pages[ enc->page_idx ] ].free;
      }
    }

    enc->root_iter = root_slist_iter_next( enc->root_iter, tc->shmem->root_ll, tc->blockcache_shmem_pool );
    if( root_slist_iter_done( enc->root_iter, tc->shmem->root_ll, tc->blockcache_shmem_pool ) ) {
      enc->state = STATE_DONE;
    } else {
      enc->state = STATE_BLOCKHASH;
    }
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
