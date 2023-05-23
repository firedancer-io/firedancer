#include "fec_set.h"

struct fd_fec_resolver {
// fd_tcache_t * done; // done_depth
// fd_tcache_t * in_progress; // depth
// fd_map_t from signatures to TT *. max size depth
// freelist of TT * . max size depth
};

ulong fd_fec_resolver_footprint( ulong depth );
ulong fd_fec_resolver_align    ( void        );

ulong fd_fec_resolver_new( void * shmem, ulong depth, fd_fec_set_t * sets );

fd_fec_resolver_t * fd_fec_resolver_join( void * shmem );

fd_fec_set_t *
fd_fec_resolver_add_shred( fd_fec_resolver_t * resolver, fd_shred_t * shred ) {
  fd_tcache * done_tcache = ctx->done_tcache;
  ulong * done_tcache_map = /* TODO */ ;
  ulong   done_tcache_map_cnt;
  /* Note: we identify FEC sets by the first 64 bits of their signature.
     Given how slow Ed25519 is and how short of a time these are
     relevant for, this seems safe, but we should research the issue
     further. */

  /* Are we already done with this FEC set? */
  ulong signature = fd_ulong_load_8( shred->signature );
  ulong found, map_idx;

  FD_TCACHE_QUERY( found, map_idx, done_tcache_map, done_tcache_map_cnt, signature );
  if( found )  return; /* With no packet loss, we expect found==1 about 50% of the time */

  fec_map_e_t * q = fec_map_query( fec_map, signature, NULL );
  TT * set = q->ptr;

  if( FD_UNLIKELY( !set ) ) {
    /* This is the first shred in the FEC set */
    if( FD_LIKELY( freelist_cnt( fec_freelist ) ) ) {
      set = freelist_pop_front( fec_freelist );
    } else {
      /* Packet loss is really high and we have a lot of in-progress FEC
         sets that we haven't been able to finish.  Take the oldest. */
      q = fec_map_query( fec_map, ip_tcache_oldest, NULL );
      if( FD_UNLIKELY( !q ) ) FD_LOG_ERR(( "data structures not in sync" ));
      set = q->ptr;
      fec_map_remove( fec_map, q );
    }

    /* Now we need to derive the root of the Merkle tree and verify the
       signature to prevent a DOS attack just by sending lots of invalid
       shreds. */
    // TODO

    if( FD_UNLIKELY( !fd_ed25519_verify( ) ) ) {
      freelist_push_front( set );
      return;
    }

    int dup;
    FD_TCACHE_INSERT( dup, ip_tcache_oldest, ip_tcache_ring, ip_tcache_depth, ip_tcache_map, ip_tcache_map_cnt, signature );
    q = fec_map_insert( fec_map, signature );
    q->ptr = set;
  } else {
    /* Validate Merkle proof, that it gives the right root. */
  }

  /* Invariants: q->ptr==set. fec_map_query( fec_map, signature )==q.
     Shred passed Merkle validation */

  // memcpy it to the right spot
  set->rx_shred_cnt++;

  if( FD_LIKELY( set->rx_shred_cnt < set->data_shred_cnt ) ) return;

  /* Create reedsol, add all shreds */

  /* At this point, the FEC set is either valid or done for good, so we
     can consider it done either way. */
  freelist_push_front( set );
  fec_map_remove( fec_map, q );
  int dup;
  FD_TCACHE_INSERT( dup, done_tcache_oldest, done_tcache_ring, done_tcache_depth, done_tcache_map, done_tcache_map_cnt, signature );

  if( FD_UNLIKELY( FD_REEDSOL_OK != fd_reedsol_recover_fini( reedsol ) ) ) {
    /* A few lines up, we already checked to make sure it wasn't the
       insufficient case, so it must be the inconsistent case.  That
       means the leader signed a shred with invalid Reed-Solomon FEC
       set.  This shouldn't happen in practice, but we need to handle it
       for the malicious leader case.  This should probably be a
       slash-able offense. */
    return;
  }
  /* Iterate over recovered shreds, add them to the Merkle tree.  If it
     fails return */

  /* Finally... A valid FEC set.  Forward it along. */
}

void * fd_fec_resolver_leave( fd_fec_resolver * resolver );
void * fd_fec_resolver_delete( void * shmem );
