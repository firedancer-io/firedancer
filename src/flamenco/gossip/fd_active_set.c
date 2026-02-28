#include "fd_active_set.h"
#include "fd_gossip_txbuild.h"
#include "fd_gossip_wsample.h"
#include "fd_bloom.h"
#include "../../util/net/fd_net_headers.h"

#define FD_ACTIVE_SET_STAKE_ENTRIES    (25UL)
#define FD_ACTIVE_SET_PEERS_PER_ENTRY  (12UL)
#define FD_ACTIVE_SET_MAX_PEERS        (FD_ACTIVE_SET_STAKE_ENTRIES*FD_ACTIVE_SET_PEERS_PER_ENTRY) /* 300 */

struct fd_active_set_peer {
  long         timestamp;
  ulong        ci_idx;
  fd_bloom_t * bloom;
  fd_gossip_txbuild_t txbuild[1];

  struct {
    ulong prev;
    ulong next;
  } dlist;
};

typedef struct fd_active_set_peer fd_active_set_peer_t;

#define DLIST_NAME  push_dlist
#define DLIST_ELE_T fd_active_set_peer_t
#define DLIST_PREV  dlist.prev
#define DLIST_NEXT  dlist.next
#include "../../util/tmpl/fd_dlist.c"

struct fd_active_set_entry {
  ulong nodes_idx; /* points to oldest entry in set */
  ulong nodes_len;
};

typedef struct fd_active_set_entry fd_active_set_entry_t;

struct __attribute__((aligned(FD_ACTIVE_SET_ALIGN))) fd_active_set_private {
  fd_active_set_entry_t entries[ FD_ACTIVE_SET_STAKE_ENTRIES ][ 1 ];
  fd_active_set_peer_t peers[ FD_ACTIVE_SET_MAX_PEERS ];

  long  next_rotate_nanos;
  ulong rotate_bucket; /* 0..24, round-robin */

  uchar identity_pubkey[ 32UL ];
  ulong identity_stake;

  fd_gossip_wsample_t * wsample;
  fd_crds_t * crds;
  fd_rng_t * rng;
  push_dlist_t * push_dlist;

  fd_gossip_send_fn send_fn;
  void *            send_fn_ctx;

  fd_active_set_metrics_t metrics[1];

  ulong magic; /* ==FD_ACTIVE_SET_MAGIC */
};

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
  l = FD_LAYOUT_APPEND( l, push_dlist_align(),  push_dlist_footprint() );
  return FD_LAYOUT_FINI( l, FD_ACTIVE_SET_ALIGN );
}

void *
fd_active_set_new( void *                shmem,
                   fd_gossip_wsample_t * wsample,
                   fd_crds_t *           crds,
                   fd_rng_t *            rng,
                   uchar const *         identity_pubkey,
                   ulong                 identity_stake,
                   fd_gossip_send_fn     send_fn,
                   void *                send_fn_ctx ) {
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
  fd_active_set_t * as       = FD_SCRATCH_ALLOC_APPEND( l, FD_ACTIVE_SET_ALIGN, sizeof(fd_active_set_t) );
  uchar * _blooms            = FD_SCRATCH_ALLOC_APPEND( l, FD_BLOOM_ALIGN,      25UL*12UL*bloom_footprint );
  push_dlist_t * _push_dlist = FD_SCRATCH_ALLOC_APPEND( l, push_dlist_align(),  push_dlist_footprint() );

  as->next_rotate_nanos = 0L;
  as->rotate_bucket     = 0UL;
  fd_memcpy( as->identity_pubkey, identity_pubkey, 32UL );
  as->identity_stake = identity_stake;

  as->wsample = wsample;
  as->crds = crds;
  as->rng = rng;
  for( ulong i=0UL; i<25UL; i++ ) {
    fd_active_set_entry_t * entry = as->entries[ i ];
    entry->nodes_idx = 0UL;
    entry->nodes_len = 0UL;

    for( ulong j=0UL; j<12UL; j++ ) {
      fd_active_set_peer_t * peer = &as->peers[ i*12UL+j ];
      peer->bloom = fd_bloom_join( fd_bloom_new( _blooms, rng, 0.1, 32768UL ) );
      if( FD_UNLIKELY( !peer->bloom ) ) {
        FD_LOG_WARNING(( "failed to create bloom filter" ));
        return NULL;
      }
      _blooms += bloom_footprint;
    }
  }

  as->push_dlist = push_dlist_join( push_dlist_new( _push_dlist ) );

  as->send_fn = send_fn;
  as->send_fn_ctx = send_fn_ctx;

  memset( as->metrics, 0, sizeof(fd_active_set_metrics_t) );

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

fd_active_set_metrics_t const *
fd_active_set_metrics( fd_active_set_t const * active_set ) {
  return active_set->metrics;
}

void
fd_active_set_set_identity( fd_active_set_t * active_set,
                            uchar const *     identity_pubkey,
                            ulong             identity_stake ) {
  fd_memcpy( active_set->identity_pubkey, identity_pubkey, 32UL );
  active_set->identity_stake = identity_stake;
}

void
fd_active_set_prune( fd_active_set_t * active_set,
                     uchar const *     push_dest,
                     uchar const *     origin,
                     ulong             origin_stake ) {
  if( FD_UNLIKELY( !memcmp( active_set->identity_pubkey, origin, 32UL ) ) ) return;

  ulong bucket = fd_active_set_stake_bucket( fd_ulong_min( active_set->identity_stake, origin_stake ) );
  for( ulong i=0UL; i<active_set->entries[ bucket ]->nodes_len; i++ ) {
    ulong peer_idx = (active_set->entries[ bucket ]->nodes_idx+i) % 12UL;
    uchar const * peer_pubkey = fd_crds_ci_pubkey( active_set->crds, active_set->peers[ bucket*12UL+peer_idx ].ci_idx );
    if( FD_UNLIKELY( !memcmp( peer_pubkey, push_dest, 32UL ) ) ) {
      fd_bloom_insert( active_set->peers[ bucket*12UL+peer_idx ].bloom, origin, 32UL );
      return;
    }
  }
}

static void
push_flush( fd_active_set_t *      active_set,
            fd_active_set_peer_t * peer,
            fd_stem_context_t *    stem,
            long                   now ) {
  if( FD_UNLIKELY( !peer->txbuild->crds_len ) ) return;

  fd_gossip_contact_info_t const * ci = fd_crds_ci( active_set->crds, peer->ci_idx );
  // TODO: Support ipv6, or prevent ending up in set
  fd_ip4_port_t dest_addr = {
    .addr = ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0U : ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4,
    .port = ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].port,
  };

  push_dlist_ele_remove( active_set->push_dlist, peer, active_set->peers );

  active_set->send_fn( active_set->send_fn_ctx, stem, peer->txbuild->bytes, peer->txbuild->bytes_len, &dest_addr, (ulong)now );

  active_set->metrics->message_tx[ peer->txbuild->tag ]++;
  active_set->metrics->message_tx_bytes[ peer->txbuild->tag ] += peer->txbuild->bytes_len+42UL; /* 42 = sizeof(fd_ip4_udp_hdrs_t) */
  for( ulong i=0UL; i<peer->txbuild->crds_len; i++ ) {
    active_set->metrics->crds_tx_push[ peer->txbuild->crds[ i ].tag ]++;
    active_set->metrics->crds_tx_push_bytes[ peer->txbuild->crds[ i ].tag ] += peer->txbuild->crds[ i ].sz;
  }

  fd_gossip_txbuild_init( peer->txbuild, active_set->identity_pubkey, FD_GOSSIP_MESSAGE_PUSH );
}

void
fd_active_set_remove_peer( fd_active_set_t * active_set,
                           ulong             ci_idx ) {
  for( ulong b=0UL; b<25UL; b++ ) {
    fd_active_set_entry_t * entry = active_set->entries[ b ];

    for( ulong i=0UL; i<entry->nodes_len; i++ ) {
      ulong peer_idx = (entry->nodes_idx+i) % 12UL;
      if( FD_UNLIKELY( active_set->peers[ b*12UL+peer_idx ].ci_idx==ci_idx ) ) {
        fd_active_set_peer_t * peer = &active_set->peers[ b*12UL+peer_idx ];
        if( FD_UNLIKELY( peer->txbuild->crds_len ) ) push_dlist_ele_remove( active_set->push_dlist, peer, active_set->peers );

        for( ulong j=i; j<entry->nodes_len-1UL; j++ ) {
          ulong from_idx = b*12UL+(entry->nodes_idx+j+1UL) % 12UL;
          ulong to_idx   = b*12UL+(entry->nodes_idx+j) % 12UL;
          fd_bloom_t * to_bloom = active_set->peers[ to_idx ].bloom;
          active_set->peers[ to_idx ] = active_set->peers[ from_idx ];
          active_set->peers[ from_idx ].bloom = to_bloom;
          /* If the moved element is in the push_dlist, fix up the
             dlist links so neighbors point to the new location.
             idx_replace reads prev/next from old_idx (from_idx, still
             intact) and patches neighbors + sentinel to reference
             to_abs instead. */
          if( FD_UNLIKELY( active_set->peers[ to_idx ].txbuild->crds_len ) ) push_dlist_idx_replace( active_set->push_dlist, to_idx, from_idx, active_set->peers );
        }
        entry->nodes_len--;
        if( FD_UNLIKELY( !entry->nodes_len ) ) entry->nodes_idx = 0UL;
        return;
      }
    }
  }
}

void
fd_active_set_push( fd_active_set_t *   active_set,
                    uchar const *       crds_val,
                    ulong               crds_sz,
                    uchar const *       origin_pubkey,
                    ulong               origin_stake,
                    fd_stem_context_t * stem,
                    long                now,
                    int                 flush_immediately ) {
  ulong stake_bucket = fd_active_set_stake_bucket( fd_ulong_min( active_set->identity_stake, origin_stake ) );
  fd_active_set_entry_t * entry = active_set->entries[ stake_bucket ];

  int originates_from_me = !memcmp( active_set->identity_pubkey, origin_pubkey, 32UL );

  for( ulong i=0UL; i<entry->nodes_len; i++ ) {
    fd_active_set_peer_t * peer = &active_set->peers[ stake_bucket*12UL+((entry->nodes_idx+i) % 12UL) ];

    /* If the value originated from us, we should always push it, even
       if theres a bloom filter hit, since bloom filters can have false
       positives and we don't want to accidentally not push our own
       values. */
    if( FD_UNLIKELY( fd_bloom_contains( peer->bloom, origin_pubkey, 32UL ) && !originates_from_me ) ) continue;

    if( FD_UNLIKELY( !fd_gossip_txbuild_can_fit( peer->txbuild, crds_sz ) ) ) push_flush( active_set, peer, stem, now );
    if( FD_UNLIKELY( !peer->txbuild->crds_len ) ) {
      peer->timestamp = now;
      push_dlist_ele_push_tail( active_set->push_dlist, peer, active_set->peers );
    }
    fd_gossip_txbuild_append( peer->txbuild, crds_sz, crds_val );
    if( FD_UNLIKELY( flush_immediately ) ) push_flush( active_set, peer, stem, now );
  }
}

static inline void
rotate_active_set( fd_active_set_t *   active_set,
                   fd_stem_context_t * stem,
                   long                now ) {
  ulong num_bloom_filter_items = fd_ulong_max( fd_crds_peer_count( active_set->crds ), 512UL );

  ulong bucket = active_set->rotate_bucket;
  active_set->rotate_bucket = (active_set->rotate_bucket+1UL) % 25UL;
  fd_active_set_entry_t * entry = active_set->entries[ bucket ];

  /* Sample a new peer BEFORE evicting the oldest.  This prevents the
     case where we evict a peer back into the sampler and then
     immediately re-sample it, creating a duplicate. */

  ulong added_ci_idx = fd_gossip_wsample_sample_remove_bucket( active_set->wsample, bucket );
  if( FD_UNLIKELY( added_ci_idx==ULONG_MAX ) ) return;

  ulong replace_idx;
  if( FD_LIKELY( entry->nodes_len==12UL ) ) {
    replace_idx      = entry->nodes_idx;
    entry->nodes_idx = (entry->nodes_idx+1UL) % 12UL;

    /* Add the replaced peer back to the sampler. */
    ulong old_ci_idx = active_set->peers[ bucket*12UL+replace_idx ].ci_idx;
    fd_gossip_wsample_add_bucket( active_set->wsample, bucket, old_ci_idx );
    push_flush( active_set, &active_set->peers[ bucket*12UL+replace_idx ], stem, now );
  } else {
    replace_idx = entry->nodes_len;
  }

  fd_active_set_peer_t * replace = &active_set->peers[ bucket*12UL+replace_idx ];
  replace->ci_idx = added_ci_idx;
  uchar const * new_pubkey = fd_crds_ci_pubkey( active_set->crds, added_ci_idx );

  fd_bloom_initialize( replace->bloom, num_bloom_filter_items );
  fd_bloom_insert( replace->bloom, new_pubkey, 32UL );
  entry->nodes_len = fd_ulong_min( entry->nodes_len+1UL, 12UL );
  fd_gossip_txbuild_init( replace->txbuild, active_set->identity_pubkey, FD_GOSSIP_MESSAGE_PUSH );
}


void
fd_active_set_advance( fd_active_set_t *   active_set,
                       fd_stem_context_t * stem,
                       long                now ) {
  while( !push_dlist_is_empty( active_set->push_dlist, active_set->peers ) ) {
    fd_active_set_peer_t * head = push_dlist_ele_peek_head( active_set->push_dlist, active_set->peers );
    if( FD_LIKELY( head->timestamp>=now-1L*1000L*1000L ) ) break;

    push_flush( active_set, head, stem, now );
  }

  if( FD_UNLIKELY( now>=active_set->next_rotate_nanos ) ) {
    rotate_active_set( active_set, stem, now );
    active_set->next_rotate_nanos = now+300L*1000L*1000L;
  }
}
