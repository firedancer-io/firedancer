#include "fd_active_set.h"
#include "fd_active_set_private.h"

FD_FN_CONST ulong
fd_active_set_align( void ) {
  return FD_ACTIVE_SET_ALIGN;
}

FD_FN_CONST ulong
fd_active_set_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACTIVE_SET_ALIGN, sizeof(fd_active_set_t) );
  l = FD_LAYOUT_APPEND( l, FD_BLOOM_ALIGN,      25UL*12UL*fd_bloom_footprint( 0.1, 32768UL ) );
  return FD_LAYOUT_FINI( l, FD_ACTIVE_SET_ALIGN );
}

void *
fd_active_set_new( void *     shmem,
                   fd_rng_t * rng ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_active_set_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong bloom_footprint = fd_bloom_footprint( 0.1, 32768UL );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_active_set_t * as = FD_SCRATCH_ALLOC_APPEND( l, FD_ACTIVE_SET_ALIGN, sizeof(fd_active_set_t) );
  uchar * _blooms = FD_SCRATCH_ALLOC_APPEND( l, FD_BLOOM_ALIGN, 25UL*12UL*bloom_footprint );

  as->rng = rng;
  for( ulong i=0UL; i<25UL; i++ ) {
    fd_active_set_entry_t * entry = as->entries[ i ];
    entry->nodes_idx = 0UL;
    entry->nodes_len = 0UL;

    for( ulong j=0UL; j<12UL; j++ ) {
      fd_active_set_peer_t * peer = entry->nodes[ j ];
      peer->bloom = fd_bloom_join( fd_bloom_new( _blooms, rng, 0.1, 32768UL ) );
      if( FD_UNLIKELY( !peer->bloom ) ) {
        FD_LOG_WARNING(( "failed to create bloom filter" ));
        return NULL;
      }
      _blooms += bloom_footprint;
    }
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( as->magic ) = FD_ACTIVE_SET_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)as;
}

fd_active_set_t *
fd_active_set_join( void * shas ) {
  if( FD_UNLIKELY( !shas ) ) {
    FD_LOG_WARNING(( "NULL shas" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shas, fd_active_set_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shas" ));
    return NULL;
  }

  fd_active_set_t * as = (fd_active_set_t *)shas;

  if( FD_UNLIKELY( as->magic!=FD_ACTIVE_SET_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return as;
}

ulong
fd_active_set_nodes( fd_active_set_t * active_set,
                     uchar const *     identity_pubkey,
                     ulong             identity_stake,
                     uchar const *     origin,
                     ulong             origin_stake,
                     int               ignore_prunes_if_peer_is_origin,
                     ulong             out_nodes[ static 12UL ] ) {
  ulong stake_bucket = fd_active_set_stake_bucket( fd_ulong_min( identity_stake, origin_stake ) );
  fd_active_set_entry_t * entry = active_set->entries[ stake_bucket ];

  int identity_eq_origin = !memcmp( identity_pubkey, origin, 32UL );

  ulong out_idx = 0UL;
  for( ulong i=0UL; i<entry->nodes_len; i++ ) {
    fd_active_set_peer_t * peer = entry->nodes[ (entry->nodes_idx+i) % 12UL ];

    int must_push_if_peer_is_origin = ignore_prunes_if_peer_is_origin && !memcmp( peer->pubkey, origin, 32UL );
    int must_push_own_values = identity_eq_origin && !memcmp( peer->pubkey, identity_pubkey, 32UL ); /* why ? */
    if( FD_UNLIKELY( fd_bloom_contains( peer->bloom, origin, 32UL ) && !must_push_own_values && !must_push_if_peer_is_origin ) ) continue;
    out_nodes[ out_idx++ ] = stake_bucket*12UL + i;
  }
  return out_idx;
}

uchar const *
fd_active_set_node_pubkey( fd_active_set_t * active_set,
                           ulong             peer_idx ){
  ulong bucket = peer_idx / FD_ACTIVE_SET_PEERS_PER_ENTRY;
  ulong idx    = peer_idx % FD_ACTIVE_SET_PEERS_PER_ENTRY;
  if( FD_UNLIKELY( bucket>=FD_ACTIVE_SET_STAKE_ENTRIES ) ) {
    FD_LOG_ERR(( "peer_idx out of range" ));
  }
  if( FD_UNLIKELY( active_set->entries[ bucket ]->nodes_len<=idx ) ) {
    FD_LOG_ERR(( "peer_idx out of range within bucket" ));
  }

  return active_set->entries[ bucket ]->nodes[ idx ]->pubkey;
}

void
fd_active_set_prunes( fd_active_set_t * active_set,
                      uchar const *     identity_pubkey,
                      ulong             identity_stake,
                      uchar const *     peers,
                      ulong             peers_len,
                      uchar const *     origin,
                      ulong             origin_stake,
                      ulong *           opt_out_node_idx ) {
  if( FD_UNLIKELY( !memcmp( identity_pubkey, origin, 32UL ) ) ) return;

  ulong bucket = fd_active_set_stake_bucket( fd_ulong_min( identity_stake, origin_stake ) );
  for( ulong i=0UL; i<12UL; i++ ) {
    if( FD_UNLIKELY( !memcmp( active_set->entries[ bucket ]->nodes[ i ]->pubkey, origin, 32UL ) ) ) {
      for( ulong j=0UL; j<peers_len; j++ ) {
        fd_bloom_insert( active_set->entries[ bucket ]->nodes[ i ]->bloom, &peers[j*32UL], 32UL );
      }
      if( opt_out_node_idx ) {
        *opt_out_node_idx = bucket*12UL + i;
      }
      return;
    }
  }
}

ulong
fd_active_set_rotate( fd_active_set_t *     active_set,
                      fd_crds_t *           crds ) {
  ulong num_bloom_filter_items = fd_ulong_max( fd_crds_peer_count( crds ), 512UL );

  ulong bucket = fd_rng_ulong_roll( active_set->rng, 25UL );
  fd_active_set_entry_t * entry = active_set->entries[ bucket ];

  ulong replace_idx;

  if( FD_LIKELY( entry->nodes_len==12UL ) ) {
    replace_idx = fd_rng_ulong_roll( active_set->rng, entry->nodes_len );
    fd_crds_bucket_add( crds, bucket, entry->nodes[ replace_idx ]->pubkey );
  } else {
    replace_idx = entry->nodes_len;
  }

  fd_active_set_peer_t * replace = entry->nodes[ replace_idx ];

  fd_contact_info_t const * new_peer = fd_crds_bucket_sample_and_remove( crds, active_set->rng, bucket );
  if( FD_UNLIKELY( !new_peer ) ) {
    return ULONG_MAX;
  }

  fd_bloom_initialize( replace->bloom, num_bloom_filter_items );
  fd_bloom_insert( replace->bloom, new_peer->pubkey.uc, 32UL );
  fd_memcpy( replace->pubkey, new_peer->pubkey.uc, 32UL );
  entry->nodes_len = fd_ulong_min( entry->nodes_len+1UL, 12UL );
  return bucket*12UL+replace_idx;
}
