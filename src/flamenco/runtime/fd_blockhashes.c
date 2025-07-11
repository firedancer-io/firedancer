#include "fd_blockhashes.h"

fd_blockhashes_t *
fd_blockhashes_recover( fd_blockhashes_t *                 blockhashes,
                        fd_block_hash_vec_global_t const * src );

static void
fd_blockhashes_pop( fd_blockhashes_t * blockhashes ) {
  if( FD_UNLIKELY( fd_blockhash_deq_empty( blockhashes->d.deque ) ) ) return;
  fd_blockhash_info_t * info = fd_blockhash_deq_pop_head_nocopy( blockhashes->d.deque );
  fd_blockhash_map_ele_remove( blockhashes->map, &info->hash, NULL, blockhashes->d.deque );
}

fd_blockhash_info_t *
fd_blockhashes_push( fd_blockhashes_t * blockhashes,
                     fd_hash_t const *  hash ) {
  if( FD_UNLIKELY( fd_blockhash_deq_full( blockhashes->d.deque ) ) ) {
    fd_blockhashes_pop( blockhashes );
  }

  fd_blockhash_info_t * info = fd_blockhash_deq_push_tail_nocopy( blockhashes->d.deque );
  *info = (fd_blockhash_info_t) { .hash = *hash };

  fd_blockhash_map_ele_insert( blockhashes->map, info, blockhashes->d.deque );

  return info;
}

FD_FN_PURE int
fd_blockhashes_check_age( fd_blockhashes_t const * blockhashes,
                          fd_hash_t const *        blockhash,
                          ulong                    max_age ) {
  fd_blockhash_info_t const * info =
      fd_blockhash_map_ele_query_const( blockhashes->map, blockhash, NULL, blockhashes->d.deque );
  if( FD_UNLIKELY( !info ) ) return 0;
  /* Derive distance from tail (end) */
  ulong base = ( blockhashes->d.end / FD_BLOCKHASHES_MAX ) * FD_BLOCKHASHES_MAX;
  ulong idx  = base + (ulong)( info - blockhashes->d.deque );
  long age   = (long)( blockhashes->d.end - idx );
  if( age<0 ) age += FD_BLOCKHASHES_MAX;
  FD_TEST( age>=0 );
  return (ulong)age <= max_age;
}
