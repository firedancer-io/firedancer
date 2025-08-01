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
