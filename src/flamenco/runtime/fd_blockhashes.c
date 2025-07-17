#include "fd_blockhashes.h"

fd_blockhashes_t *
fd_blockhashes_init( fd_blockhashes_t * mem,
                     ulong              seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  FD_TEST( fd_blockhash_deq_join( fd_blockhash_deq_new( &mem->d ) ) );
  memset( mem->d.deque, 0x5a, sizeof(fd_blockhash_info_t) * FD_BLOCKHASHES_MAX );
  FD_TEST( fd_blockhash_map_join( fd_blockhash_map_new( mem, FD_BLOCKHASH_MAP_CHAIN_MAX, seed ) ) );
  return mem;
}

fd_blockhashes_t *
fd_blockhashes_recover( fd_blockhashes_t *              blockhashes,
                        fd_hash_hash_age_pair_t const * ages,
                        ulong                           age_cnt,
                        ulong                           seed ) {
  FD_TEST( fd_blockhashes_init( blockhashes, seed ) );
  if( FD_UNLIKELY( !age_cnt || age_cnt>FD_BLOCKHASHES_MAX ) ) {
    FD_LOG_WARNING(( "Corrupt snapshot: blockhash queue age count %lu is out of range [1,%d)", age_cnt, FD_BLOCKHASHES_MAX ));
  }

  /* For depressing reasons, the ages array is not sorted when ingested
     from a snapshot.  The hash_index field is also not validated.
     Firedancer assumes that the sequence of hash_index numbers is
     gapless and does not wrap around. */

  ulong seq_min = ULONG_MAX-1;
  for( ulong i=0UL; i<age_cnt; i++ ) {
    seq_min = fd_ulong_min( seq_min, ages[i].val.hash_index );
  }
  ulong seq_max;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( seq_min, age_cnt, &seq_max ) ) ) {
    FD_LOG_WARNING(( "Corrupt snapshot: blockhash queue sequence number wraparound (seq_min=%lu age_cnt=%lu)", seq_min, age_cnt ));
    return NULL;
  }

  /* Reset */

  for( ulong i=0UL; i<age_cnt; i++ ) {
    fd_blockhash_info_t * ele = fd_blockhash_deq_push_tail_nocopy( blockhashes->d.deque );
    memset( ele, 0, sizeof(fd_blockhash_info_t) );
  }

  /* Load hashes */

  for( ulong i=0UL; i<age_cnt; i++ ) {
    fd_hash_hash_age_pair_t const * elem = &ages[i];
    ulong idx;
    if( FD_UNLIKELY( __builtin_usubl_overflow( elem->val.hash_index, seq_min, &idx ) ) ) {
      FD_LOG_WARNING(( "Corrupt snapshot: gap in blockhash queue (seq=[%lu,%lu) idx=%lu)",
                       seq_min, seq_max, elem->val.hash_index ));
      return NULL;
    }
    fd_blockhash_info_t * info = &blockhashes->d.deque[ idx ];
    if( FD_UNLIKELY( info->exists ) ) {
      FD_LOG_HEXDUMP_NOTICE(( "info", info, sizeof(fd_blockhash_info_t) ));
      FD_LOG_WARNING(( "Corrupt snapshot: duplicate blockhash queue index %lu", idx ));
      return NULL;
    }
    info->exists         = 1;
    info->hash           = elem->key;
    info->fee_calculator = elem->val.fee_calculator;
    fd_blockhash_map_idx_insert( blockhashes->map, idx, blockhashes->d.deque );
  }

  return blockhashes;
}

static void
fd_blockhashes_pop_old( fd_blockhashes_t * blockhashes ) {
  if( FD_UNLIKELY( fd_blockhash_deq_empty( blockhashes->d.deque ) ) ) return;
  fd_blockhash_info_t * info = fd_blockhash_deq_pop_head_nocopy( blockhashes->d.deque );
  info->exists = 0;
  fd_blockhash_map_ele_remove( blockhashes->map, &info->hash, NULL, blockhashes->d.deque );
}

void
fd_blockhashes_pop_new( fd_blockhashes_t * blockhashes ) {
  if( FD_UNLIKELY( fd_blockhash_deq_empty( blockhashes->d.deque ) ) ) return;
  fd_blockhash_info_t * info = fd_blockhash_deq_pop_tail_nocopy( blockhashes->d.deque );
  info->exists = 0;
  fd_blockhash_map_ele_remove( blockhashes->map, &info->hash, NULL, blockhashes->d.deque );
}

fd_blockhash_info_t *
fd_blockhashes_push_new( fd_blockhashes_t * blockhashes,
                         fd_hash_t const *  hash ) {
  if( FD_UNLIKELY( fd_blockhash_deq_full( blockhashes->d.deque ) ) ) {
    fd_blockhashes_pop_old( blockhashes );
  }
  if( FD_UNLIKELY( fd_blockhash_map_idx_query( blockhashes->map, hash, ULONG_MAX, blockhashes->d.deque )!=ULONG_MAX ) ) {
    char bh_cstr[ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( hash->uc, NULL, bh_cstr );
    FD_LOG_CRIT(( "Attempted to register duplicate blockhash %s", bh_cstr ));
  }

  fd_blockhash_info_t * info = fd_blockhash_deq_push_tail_nocopy( blockhashes->d.deque );
  *info = (fd_blockhash_info_t) { .hash = *hash, .exists = 1 };

  fd_blockhash_map_ele_insert( blockhashes->map, info, blockhashes->d.deque );

  return info;
}

fd_blockhash_info_t *
fd_blockhashes_push_old( fd_blockhashes_t * blockhashes,
                         fd_hash_t const *  hash ) {
  if( FD_UNLIKELY( fd_blockhash_deq_full( blockhashes->d.deque ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( fd_blockhash_map_idx_query( blockhashes->map, hash, ULONG_MAX, blockhashes->d.deque )!=ULONG_MAX ) ) {
    char bh_cstr[ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( hash->uc, NULL, bh_cstr );
    FD_LOG_CRIT(( "Attempted to register duplicate blockhash %s", bh_cstr ));
  }

  fd_blockhash_info_t * info = fd_blockhash_deq_push_head_nocopy( blockhashes->d.deque );
  *info = (fd_blockhash_info_t) { .hash = *hash, .exists = 1 };

  fd_blockhash_map_ele_insert( blockhashes->map, info, blockhashes->d.deque );

  return info;
}


FD_FN_PURE int
fd_blockhashes_check_age( fd_blockhashes_t const * blockhashes,
                          fd_hash_t const *        blockhash,
                          ulong                    max_age ) {
  ulong const idx = fd_blockhash_map_idx_query_const( blockhashes->map, blockhash, ULONG_MAX, blockhashes->d.deque );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return 0;
  /* Derive distance from tail (end) */
  ulong const max = fd_blockhash_deq_max( blockhashes->d.deque );
  ulong const end = (blockhashes->d.end - 1) & (max-1);
  ulong const age = end + fd_ulong_if( idx<=end, 0UL, max ) - idx;
  return age<=max_age;
}
