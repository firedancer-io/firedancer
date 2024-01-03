#include "tiles.h"

#include "generated/shred_seccomp.h"
#include "../../../../disco/shred/fd_shredder.h"
#include "../../../../disco/shred/fd_shred_dest.h"
#include "../../../../disco/shred/fd_fec_resolver.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../tango/ip/fd_ip.h"

#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"

#include <linux/unistd.h>

/* The shred tile handles shreds from two data sources: shreds
   generated from microblocks from the banking tile, and shreds
   retransmitted from the network.

   They have rather different semantics, but at the end of the day, they
   both result in a bunch of shreds and FEC sets that need to be sent to
   the blockstore and on the network, which is why one tile handles
   both.

   We segment the memory for the two types of shreds into two halves of
   a dcache because they follow somewhat different flow control
   patterns. For flow control, the normal guarantee we want to provide
   is that the dcache entry is not overwritten unless the mcache entry
   has also been overwritten.  The normal way to do this when using both
   cyclically and with a 1-to-1 mapping is to make the dcache at least
   `burst` entries bigger than the mcache.

   In this tile, we use one output mcache with one output dcache (which
   is logically partitioned into two) for the two sources of data.  The
   worst case for flow control is when we're only sending with one of
   the dcache partitions at a time though, so we can consider them
   separately.

   From bank: Every FEC set triggers at least two mcache entries (one
   for parity and one for data), so at most, we have ceil(mcache
   depth/2) FEC sets exposed.  This means we need to decompose dcache
   into at least ceil(mcache depth/2)+1 FEC sets.

   From the network: The FEC resolver doesn't use a cyclic order, but it
   does promise that once it returns an FEC set, it will return at least
   complete_depth FEC sets before returning it again.  This means we
   want at most complete_depth-1 FEC sets exposed, so
   complete_depth=ceil(mcache depth/2)+1 FEC sets as above.  The FEC
   resolver has the ability to keep individual shreds for partial_depth
   calls, but because in this version of the shred tile, we send each
   shred to all its destinations as soon as we get it, we don't need
   that functionality, so we set partial_depth=1.

   Adding these up, we get 2*ceil(mcache_depth/2)+3+fec_resolver_depth
   FEC sets, which is no more than mcache_depth+4+fec_resolver_depth.
   Each FEC is paired with 4 fd_shred34_t structs, so that means we need
   to decompose the dcache into 4*mcache_depth + 4*fec_resolver_depth +
   16 fd_shred34_t structs. */


/* The memory this tile uses is a bit complicated and has some logical
   aliasing to facilitate zero-copy use.  We have a dcache containing
   fd_shred34_t objects, which are basically 34 fd_shred_t objects
   padded to their max size, where 34 is set so that the size of the
   fd_shred34_t object (including some metadata) is less than
   USHORT_MAX, which facilitates sending it using Tango.  Then, for each
   set of 4 consecutive fd_shred34_t objects, we have an fd_fec_set_t.
   The first 34 data shreds point to the payload section of the payload
   section of each of the packets in the first fd_shred34_t.  The other
   33 data shreds point into the second fd_shred34_t.  Similar for the
   parity shreds pointing into the third and fourth fd_shred34_t. */

/* There's nothing deep about this max, but I just find it easier to
   have a max and use statically sized arrays than alloca. */
#define MAX_BANK_CNT 64UL

/* MAX_SHRED_DESTS indicates the maximum number of destinations (i.e. a
   pubkey -> ip, port) that the shred tile can keep track of. */
#define MAX_SHRED_DESTS 40200UL

#define FD_SHRED_TILE_SCRATCH_ALIGN 128UL


#define NET_IN_IDX      0
#define POH_IN_IDX      1
#define STAKE_IN_IDX    2
#define CONTACT_IN_IDX  3
#define SIGN_IN_IDX   4

#define NET_OUT_IDX     0
#define SIGN_OUT_IDX    1

#define MAX_SLOTS_PER_EPOCH 432000UL

#define DCACHE_ENTRIES_PER_FEC_SET (4UL)
FD_STATIC_ASSERT( sizeof(fd_shred34_t) < USHORT_MAX, shred_34 );
FD_STATIC_ASSERT( 34*DCACHE_ENTRIES_PER_FEC_SET >= FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX, shred_34 );
FD_STATIC_ASSERT( sizeof(fd_shred34_t) == FD_SHRED_STORE_MTU, shred_34 );

FD_STATIC_ASSERT( sizeof(fd_entry_batch_meta_t)==24UL, poh_shred_mtu );

/* Part 2: Shred destinations */
struct __attribute__((packed)) fd_shred_dest_wire {
  uchar  pubkey[32];
  /* The Labs splice writes this as octets, which means when we read
     this, it's essentially network byte order */
  uint   ip4_addr;
  ushort udp_port;
};
typedef struct fd_shred_dest_wire fd_shred_dest_wire_t;

typedef struct __attribute__((packed)) {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];
} eth_ip_udp_t;



typedef struct {
  fd_shredder_t      * shredder;
  fd_fec_resolver_t  * resolver;
  fd_pubkey_t          identity_key[1]; /* Just the public key */

  fd_keyguard_client_t keyguard_client[1];

  uint                 src_ip_addr;
  uchar                src_mac_addr[ 6 ];
  ushort               shred_listen_port;
  fd_ip_t            * ip;

  /* shred34 and fec_sets are very related: fec_sets[i] has pointers
     to the shreds in shred34[4*i + k] for k=0,1,2,3. */
  fd_shred34_t       * shred34;
  fd_fec_set_t       * fec_sets;

  fd_stake_ci_t      * stake_ci;
  /* These are used in between during_frag and after_frag */
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  ushort net_id;

  eth_ip_udp_t data_shred_net_hdr  [1];
  eth_ip_udp_t parity_shred_net_hdr[1];

  fd_wksp_t * shred_store_wksp;

  ulong shredder_fec_set_idx;     /* In [0, shredder_max_fec_set_idx) */
  ulong shredder_max_fec_set_idx; /* exclusive */

  ulong send_fec_set_idx;
  ulong tsorig;  /* timestamp of the last packet in compressed form */

  /* Includes Ethernet, IP, UDP headers */
  ulong shred_buffer_sz;
  uchar shred_buffer[ FD_NET_MTU ];

  fd_wksp_t * net_in_mem;
  ulong       net_in_chunk0;
  ulong       net_in_wmark;

  fd_wksp_t * stake_in_mem;
  ulong       stake_in_chunk0;
  ulong       stake_in_wmark;

  fd_wksp_t * contact_in_mem;
  ulong       contact_in_chunk0;
  ulong       contact_in_wmark;

  fd_wksp_t * poh_in_mem;
  ulong       poh_in_chunk0;
  ulong       poh_in_wmark;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * store_out_mem;
  ulong       store_out_chunk0;
  ulong       store_out_wmark;
  ulong       store_out_chunk;

  struct {
    ulong pos; /* in payload, so 0<=pos<63671 */
    ulong slot; /* set to 0 when pos==0 */
    union {
      struct {
        ulong microblock_cnt;
        uchar payload[ 63679UL - 8UL ];
      };
      uchar raw[ 63679UL ]; /* The largest that fits in 1 FEC set */
    };
  } pending_batch;
} fd_shred_ctx_t;

/* PENDING_BATCH_WMARK: Following along the lines of dcache, batch
   microblocks until either the slot ends or we excede the watermark.
   We know that if we're <= watermark, we can always accept a message of
   maximum size. */
#define PENDING_BATCH_WMARK (63679UL - 8UL - FD_POH_SHRED_MTU)

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {

  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, tile->shred.depth,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong fec_set_cnt = tile->shred.depth + tile->shred.fec_resolver_depth + 4UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_shred_ctx_t),          sizeof(fd_shred_ctx_t)                  );
  l = FD_LAYOUT_APPEND( l, fd_ip_align(),                    fd_ip_footprint( 256UL, 256UL )         );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()                 );
  l = FD_LAYOUT_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint                  );
  l = FD_LAYOUT_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()                 );
  l = FD_LAYOUT_APPEND( l, alignof(fd_fec_set_t),            sizeof(fd_fec_set_t)*fec_set_cnt        );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_shred_ctx_t ) );
}

static inline void
handle_new_cluster_contact_info( fd_shred_ctx_t * ctx,
                           uchar const    * buf ) {
  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = header[ 0 ];

  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_SHRED_DESTS ));

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header+1UL );
  fd_shred_dest_weighted_t * dests = fd_stake_ci_dest_add_init( ctx->stake_ci );

  ctx->new_dest_ptr = dests;
  ctx->new_dest_cnt = dest_cnt;

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    memcpy( dests[i].pubkey.uc, in_dests[i].pubkey, 32UL );
    dests[i].ip4  = in_dests[i].ip4_addr;
    dests[i].port = in_dests[i].udp_port;
  }
}

static inline void
finalize_new_cluster_contact_info( fd_shred_ctx_t * ctx ) {

  fd_shred_dest_weighted_t * dests    = ctx->new_dest_ptr;
  ulong                      dest_cnt = ctx->new_dest_cnt;

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    /* Resolve the destination */
    int can_send_to_dest = 0;
    if( FD_LIKELY( dests[i].ip4 ) ) {

      uint out_next_ip[1];
      uint out_ifindex[1];
      int res = fd_ip_route_ip_addr( dests[i].mac_addr, out_next_ip, out_ifindex, ctx->ip, dests[i].ip4 );

      if( FD_LIKELY( res==FD_IP_SUCCESS ) ) {
        can_send_to_dest = 1;
      }
      else if( FD_LIKELY( res==FD_IP_PROBE_RQD ) ) {
        uchar * arp_packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
        ulong arp_sz[1];
        res = fd_ip_arp_gen_arp_probe( arp_packet, sizeof(fd_ip_arp_t), arp_sz, *out_next_ip, ctx->src_ip_addr, ctx->src_mac_addr );
        if( res!=FD_IP_SUCCESS ) FD_LOG_ERR(( "Generation of arp probe failed" ));

        ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
        ulong   sig = fd_disco_netmux_sig( 0U, 0U, FD_NETMUX_SIG_IGNORE_HDR_SZ, SRC_TILE_SHRED, (ushort)0 ); /* arp is not IP */
        fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk,
            *arp_sz, 0UL, 0UL, tspub );
        ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
        ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, *arp_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
      } else {
        /* increment counter */
      }
    }
    if( FD_UNLIKELY( !can_send_to_dest ) ) {
      dests[i].ip4  =         0U;
      dests[i].port = (ushort)0 ;
      memset( dests[i].mac_addr, 0, 6UL );
    }
  }

  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)seq;

  fd_shred_ctx_t * ctx = (fd_shred_ctx_t *)_ctx;

  if( FD_LIKELY( in_idx==NET_IN_IDX ) ) {
    *opt_filter = fd_disco_netmux_sig_port( sig )!=ctx->shred_listen_port;
  } else if( FD_LIKELY( in_idx==POH_IN_IDX ) ) {
    *opt_filter = fd_disco_poh_sig_pkt_type( sig )!=POH_PKT_TYPE_MICROBLOCK;
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)opt_filter;

  fd_shred_ctx_t * ctx = (fd_shred_ctx_t *)_ctx;

  ctx->tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  if( FD_UNLIKELY( in_idx==SIGN_IN_IDX ) ) {
    FD_LOG_CRIT(( "signing tile send out of band fragment" ));
  }

  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->contact_in_chunk0 || chunk>ctx->contact_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->contact_in_chunk0, ctx->contact_in_wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->contact_in_mem, chunk );
    handle_new_cluster_contact_info( ctx, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in_chunk0 || chunk>ctx->stake_in_wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_in_chunk0, ctx->stake_in_wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_in_mem, chunk );
    fd_stake_ci_stake_msg_init( ctx->stake_ci, dcache_entry );
    return;
  }

  if( FD_UNLIKELY( in_idx==POH_IN_IDX ) ) {
    /* This is a frag from the PoH tile.  We'll copy it to our pending
       microblock batch and shred it if necessary (last in block or
       above watermark).  We just go ahead and shred it here, even
       though we may get overrun.  If we do end up getting overrun, we
       just won't send these shreds out and we'll reuse the FEC set for
       the next one.  From a higher level though, if we do get overrun,
       a bunch of shreds will never be transmitted, and we'll end up
       producing a block that never lands on chain. */
    fd_fec_set_t * out = ctx->fec_sets + ctx->shredder_fec_set_idx;

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->poh_in_mem, chunk );
    if( FD_UNLIKELY( chunk<ctx->poh_in_chunk0 || chunk>ctx->poh_in_wmark ) || sz>FD_POH_SHRED_MTU )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->poh_in_chunk0, ctx->poh_in_wmark ));

    fd_entry_batch_meta_t const * entry_meta = (fd_entry_batch_meta_t const *)dcache_entry;
    uchar const *                 entry      = dcache_entry + sizeof(fd_entry_batch_meta_t);
    ulong                         entry_sz   = sz           - sizeof(fd_entry_batch_meta_t);

    /* It should never be possible for this to fail, but we check it
       anyway. */
    FD_TEST( entry_sz + ctx->pending_batch.pos <= sizeof(ctx->pending_batch.payload) );

    ulong target_slot = fd_disco_poh_sig_slot( sig );
    if( FD_UNLIKELY( (ctx->pending_batch.microblock_cnt>0) & (ctx->pending_batch.slot!=target_slot) ) ) {
      /* TODO: The Labs client sends a dummy entry batch with only 1
         byte and the block-complete bit set.  This helps other
         validators know that the block is dead and they should not try
         to continue building a fork on it.  We probably want a similar
         approach eventually. */
      FD_LOG_WARNING(( "Abandoning %lu microblocks for slot %lu and switching to slot %lu",
            ctx->pending_batch.microblock_cnt, ctx->pending_batch.slot, target_slot ));
      ctx->pending_batch.slot           = 0UL;
      ctx->pending_batch.pos            = 0UL;
      ctx->pending_batch.microblock_cnt = 0UL;
    }

    ctx->pending_batch.slot = target_slot;
    /* Ugh, yet another memcpy */
    fd_memcpy( ctx->pending_batch.payload + ctx->pending_batch.pos, entry, entry_sz );
    ctx->pending_batch.pos += entry_sz;
    ctx->pending_batch.microblock_cnt++;

    int last_in_batch = entry_meta->block_complete | (ctx->pending_batch.pos > PENDING_BATCH_WMARK);

    if( FD_UNLIKELY( last_in_batch )) {
      fd_shredder_init_batch( ctx->shredder, ctx->pending_batch.raw, sizeof(ulong)+ctx->pending_batch.pos, target_slot, entry_meta );

      /* We sized this so it fits in one FEC set */
      FD_TEST( fd_shredder_next_fec_set( ctx->shredder, out ) );
      fd_shredder_fini_batch( ctx->shredder );

      d_rcvd_join( d_rcvd_new( d_rcvd_delete( d_rcvd_leave( out->data_shred_rcvd   ) ) ) );
      p_rcvd_join( p_rcvd_new( p_rcvd_delete( p_rcvd_leave( out->parity_shred_rcvd ) ) ) );

      ctx->send_fec_set_idx = ctx->shredder_fec_set_idx;

      /* reset state */
      ctx->pending_batch.slot           = 0UL;
      ctx->pending_batch.pos            = 0UL;
      ctx->pending_batch.microblock_cnt = 0UL;
    } else {
      ctx->send_fec_set_idx = ULONG_MAX;
    }
  } else { /* the common case, from the netmux tile */
    /* The FEC resolver API does not present a prepare/commit model. If we
       get overrun between when the FEC resolver verifies the signature
       and when it stores the local copy, we could end up storing and
       retransmitting garbage.  Instead we copy it locally, sadly, and
       only give it to the FEC resolver when we know it won't be overrun
       anymore. */
    if( FD_UNLIKELY( chunk<ctx->net_in_chunk0 || chunk>ctx->net_in_wmark || sz>FD_NET_MTU ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->net_in_chunk0, ctx->net_in_wmark ));
    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->net_in_mem, chunk );
    ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    FD_TEST( hdr_sz < sz ); /* Should be ensured by the net tile */
    fd_memcpy( ctx->shred_buffer, dcache_entry+hdr_sz, sz-hdr_sz );
    ctx->shred_buffer_sz = sz-hdr_sz;
  }
}

static inline void
send_shred( fd_shred_ctx_t *      ctx,
            fd_shred_t const    * shred,
            fd_shred_dest_t     * sdest,
            fd_shred_dest_idx_t   dest_idx,
            ulong                 tsorig ) {
  fd_shred_dest_weighted_t * dest = fd_shred_dest_idx_to_dest( sdest, dest_idx );

  if( FD_UNLIKELY( !dest->ip4 ) ) return;

  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );

  int is_data = fd_shred_type( shred->variant )==FD_SHRED_TYPE_MERKLE_DATA;
  eth_ip_udp_t * tmpl = fd_ptr_if( is_data, (eth_ip_udp_t *)ctx->data_shred_net_hdr,
                                            (eth_ip_udp_t *)ctx->parity_shred_net_hdr );
  fd_memcpy( packet, tmpl, sizeof(eth_ip_udp_t) );

  eth_ip_udp_t * hdr = (eth_ip_udp_t *)packet;

  memcpy( hdr->eth->dst, dest->mac_addr, 6UL );

  memcpy( hdr->ip4->daddr_c, &dest->ip4, 4UL );
  hdr->ip4->net_id     = fd_ushort_bswap( ctx->net_id++ );
  hdr->ip4->check      = 0U;
  hdr->ip4->check      = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( hdr->ip4 ) );

  hdr->udp->net_dport  = fd_ushort_bswap( dest->port );

  ulong shred_sz = fd_ulong_if( is_data, FD_SHRED_MIN_SZ, FD_SHRED_MAX_SZ );
  fd_memcpy( packet+sizeof(eth_ip_udp_t), shred, shred_sz );

  ulong pkt_sz = shred_sz + sizeof(eth_ip_udp_t);

  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong   sig = fd_disco_netmux_sig( dest->ip4, dest->port, FD_NETMUX_SIG_MIN_HDR_SZ, SRC_TILE_SHRED, (ushort)0 );
  fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk,
      pkt_sz, 0UL, tsorig, tspub );
  ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, pkt_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_sig;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_tsorig;
  (void)opt_filter;

  fd_shred_ctx_t * ctx = (fd_shred_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx==CONTACT_IN_IDX ) ) {
    finalize_new_cluster_contact_info( ctx );
    return;
  }

  if( FD_UNLIKELY( in_idx==STAKE_IN_IDX ) ) {
    fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    return;
  }

  if( FD_UNLIKELY( (in_idx==POH_IN_IDX) & (ctx->send_fec_set_idx==ULONG_MAX) ) ) {
    /* Entry from PoH that didn't trigger a new FEC set to be made */
    return;
  }

  const ulong fanout = 200UL;
  fd_shred_dest_idx_t _dests[ 200*(FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX) ];

  if( FD_LIKELY( in_idx==NET_IN_IDX ) ) {
    uchar * shred_buffer    = ctx->shred_buffer;
    ulong   shred_buffer_sz = ctx->shred_buffer_sz;

    fd_shred_t const * shred = fd_shred_parse( shred_buffer, shred_buffer_sz );
    if( FD_UNLIKELY( !shred ) ) return;

    fd_epoch_leaders_t const * lsched = fd_stake_ci_get_lsched_for_slot( ctx->stake_ci, shred->slot );
    if( FD_UNLIKELY( !lsched ) ) return;

    fd_pubkey_t const * slot_leader = fd_epoch_leaders_get( lsched, shred->slot );
    if( FD_UNLIKELY( !slot_leader ) ) return;

    fd_fec_set_t const * out_fec_set[ 1 ];
    fd_shred_t   const * out_shred[ 1 ];
    int rv = fd_fec_resolver_add_shred( ctx->resolver, shred, shred_buffer_sz, slot_leader->uc, out_fec_set, out_shred );

    if( (rv==FD_FEC_RESOLVER_SHRED_OKAY) | (rv==FD_FEC_RESOLVER_SHRED_COMPLETES) ) {
      /* Relay this shred */
      ulong fanout = 200UL;
      ulong max_dest_cnt[1];
      fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, shred->slot );
      if( FD_UNLIKELY( !sdest ) ) return;
      fd_shred_dest_idx_t * dests = fd_shred_dest_compute_children( sdest, &shred, 1UL, _dests, 1UL, fanout, fanout, max_dest_cnt );
      if( FD_UNLIKELY( !dests ) ) return;

      for( ulong j=0UL; j<*max_dest_cnt; j++ ) send_shred( ctx, *out_shred, sdest, dests[ j ], ctx->tsorig );
    }
    if( FD_LIKELY( rv!=FD_FEC_RESOLVER_SHRED_COMPLETES ) ) return;

    FD_TEST( ctx->fec_sets <= *out_fec_set );
    ctx->send_fec_set_idx = (ulong)(*out_fec_set - ctx->fec_sets);
  } else {
    /* We know we didn't get overrun, so advance the index */
    ctx->shredder_fec_set_idx = (ctx->shredder_fec_set_idx+1UL)%ctx->shredder_max_fec_set_idx;
  }
  /* If this was the shred that completed an FEC set or this was a
     microblock we shredded ourself, we now have a full FEC set that we
     need to send to the blockstore and on the network (skipping any
     shreds we already sent). */

  fd_fec_set_t * set = ctx->fec_sets + ctx->send_fec_set_idx;
  fd_shred34_t * s34 = ctx->shred34 + 4UL*ctx->send_fec_set_idx;

  s34[ 0 ].shred_cnt =                         fd_ulong_min( set->data_shred_cnt,   34UL );
  s34[ 1 ].shred_cnt = set->data_shred_cnt   - fd_ulong_min( set->data_shred_cnt,   34UL );
  s34[ 2 ].shred_cnt =                         fd_ulong_min( set->parity_shred_cnt, 34UL );
  s34[ 3 ].shred_cnt = set->parity_shred_cnt - fd_ulong_min( set->parity_shred_cnt, 34UL );

  /* Send to the blockstore, skipping any empty shred34_t s. */
  ulong sig = 0UL;
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_mux_publish( mux, sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+0UL ), sizeof(fd_shred34_t), 0UL, ctx->tsorig, tspub );
  if( FD_UNLIKELY( s34[ 1 ].shred_cnt ) )
    fd_mux_publish( mux, sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+1UL ), sizeof(fd_shred34_t), 0UL, ctx->tsorig, tspub );
  fd_mux_publish( mux, sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+2UL), sizeof(fd_shred34_t), 0UL, ctx->tsorig, tspub );
  if( FD_UNLIKELY( s34[ 3 ].shred_cnt ) )
    fd_mux_publish( mux, sig, fd_laddr_to_chunk( ctx->store_out_mem, s34+3UL ), sizeof(fd_shred34_t), 0UL, ctx->tsorig, tspub );

  /* Compute all the destinations for all the new shreds */

  fd_shred_t const * new_shreds[ FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX ];
  ulong k=0UL;
  for( ulong i=0UL; i<set->data_shred_cnt; i++ )
    if( !d_rcvd_test( set->data_shred_rcvd,   i ) )  new_shreds[ k++ ] = (fd_shred_t const *)set->data_shreds  [ i ];
  for( ulong i=0UL; i<set->parity_shred_cnt; i++ )
    if( !p_rcvd_test( set->parity_shred_rcvd, i ) )  new_shreds[ k++ ] = (fd_shred_t const *)set->parity_shreds[ i ];

  if( FD_UNLIKELY( !k ) ) return;
  fd_shred_dest_t * sdest = fd_stake_ci_get_sdest_for_slot( ctx->stake_ci, new_shreds[ 0 ]->slot );
  if( FD_UNLIKELY( !sdest ) ) return;

  ulong out_stride;
  ulong max_dest_cnt[1];
  fd_shred_dest_idx_t * dests;
  if( FD_LIKELY( in_idx==NET_IN_IDX ) ) {
    out_stride = k;
    dests = fd_shred_dest_compute_children( sdest, new_shreds, k, _dests, k, fanout, fanout, max_dest_cnt );
  } else {
    out_stride = 1UL;
    *max_dest_cnt = 1UL;
    dests = fd_shred_dest_compute_first   ( sdest, new_shreds, k, _dests );
  }
  FD_TEST( dests );

  /* Send only the ones we didn't receive. */
  for( ulong i=0UL; i<k; i++ ) for( ulong j=0UL; j<*max_dest_cnt; j++ ) send_shred( ctx, new_shreds[ i ], sdest, dests[ j*out_stride+i ], ctx->tsorig );
}

static inline void
warmup_arp_cache( fd_shred_ctx_t * ctx ) {
  FD_LOG_NOTICE(( "Trying to find route to 1.1.1.1 to warmup the arp cache" ));
  fd_ip_t * ip = ctx->ip;
  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  while( 1 ) {
    uchar mac[6];
    uint  out_next_ip[1];
    uint  out_ifindex[1];

    fd_ip_route_fetch( ip );
    fd_ip_arp_fetch  ( ip );
    int res = fd_ip_route_ip_addr( mac, out_next_ip, out_ifindex, ip, 0x01010101 );
    if( res==FD_IP_NO_ROUTE  ) { FD_LOG_WARNING(( "No route to 1.1.1.1. Skipping warmup." )); return; }
    if( res==FD_IP_SUCCESS   ) break;
    if( res!=FD_IP_PROBE_RQD ) FD_LOG_ERR(( "Unicast address resolved to multicast/broadcast" ));

    uchar * arp_packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    ulong arp_sz[1];
    res = fd_ip_arp_gen_arp_probe( arp_packet, sizeof(fd_ip_arp_t), arp_sz, *out_next_ip, ctx->src_ip_addr, ctx->src_mac_addr );
    if( res!=FD_IP_SUCCESS ) FD_LOG_ERR(( "Generation of arp probe failed" ));

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    ulong   sig = fd_disco_netmux_sig( 0U, 0U, FD_NETMUX_SIG_IGNORE_HDR_SZ, SRC_TILE_SHRED, (ushort)0 ); /* arp is not IP */
    fd_mcache_publish( ctx->net_out_mcache, ctx->net_out_depth, ctx->net_out_seq, sig, ctx->net_out_chunk,
        *arp_sz, 0UL, tsorig, tspub );
    ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
    ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, *arp_sz, ctx->net_out_chunk0, ctx->net_out_wmark );

    long spin_start = fd_log_wallclock();
    while( fd_log_wallclock() - spin_start < 1000000L ) FD_SPIN_PAUSE(); /* Pause for at least 1 millisecond */
  }
  FD_LOG_NOTICE(( "ARP cache warmed" ));
}
static inline void
populate_packet_header_template( eth_ip_udp_t * pkt,
                                 ulong          shred_payload_sz,
                                 uint           src_ip,
                                 uchar const *  src_mac,
                                 ushort         src_port ) {
  memset( pkt->eth->dst, 0,       6UL );
  memcpy( pkt->eth->src, src_mac, 6UL );
  pkt->eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

  pkt->ip4->verihl       = FD_IP4_VERIHL( 4U, 5U );
  pkt->ip4->tos          = (uchar)0;
  pkt->ip4->net_tot_len  = fd_ushort_bswap( (ushort)(shred_payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  pkt->ip4->net_frag_off = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
  pkt->ip4->ttl          = (uchar)64;
  pkt->ip4->protocol     = FD_IP4_HDR_PROTOCOL_UDP;
  pkt->ip4->check        = 0U;
  memcpy( pkt->ip4->saddr_c, &src_ip, 4UL );
  memset( pkt->ip4->daddr_c, 0,       4UL ); /* varies by shred */

  pkt->udp->net_sport = fd_ushort_bswap( src_port );
  pkt->udp->net_dport = (ushort)0; /* varies by shred */
  pkt->udp->net_len   = fd_ushort_bswap( (ushort)(shred_payload_sz + sizeof(fd_udp_hdr_t)) );
  pkt->udp->check     = (ushort)0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );
  ctx->ip = fd_ip_join( fd_ip_new( FD_SCRATCH_ALLOC_APPEND( l, fd_ip_align(), fd_ip_footprint( 256UL, 256UL ) ), 256UL, 256UL ) );
  if( FD_UNLIKELY( !ctx->ip ) ) FD_LOG_ERR(( "fd_ip_join failed" ));

  if( FD_UNLIKELY( !strcmp( tile->shred.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t *)load_key_into_protected_memory( tile->shred.identity_key_path, /* pubkey only: */ 1 );
}

void
fd_shred_signer( void *        signer_ctx,
                 uchar         signature[ static 64 ],
                 uchar const   merkle_root[ static 32 ] ) {
  fd_keyguard_client_sign( signer_ctx, signature, merkle_root, 32UL );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( tile->in_cnt != 5 ||
                   topo->links[ tile->in_link_id[ NET_IN_IDX     ] ].kind != FD_TOPO_LINK_KIND_NETMUX_TO_OUT    ||
                   topo->links[ tile->in_link_id[ POH_IN_IDX     ] ].kind != FD_TOPO_LINK_KIND_POH_TO_SHRED     ||
                   topo->links[ tile->in_link_id[ STAKE_IN_IDX   ] ].kind != FD_TOPO_LINK_KIND_STAKE_TO_OUT     ||
                   topo->links[ tile->in_link_id[ CONTACT_IN_IDX ] ].kind != FD_TOPO_LINK_KIND_CRDS_TO_SHRED    ||
                   topo->links[ tile->in_link_id[ SIGN_IN_IDX    ] ].kind != FD_TOPO_LINK_KIND_SIGN_TO_SHRED ) )
    FD_LOG_ERR(( "shred tile has none or unexpected input links %lu %lu %lu",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].kind, topo->links[ tile->in_link_id[ 1 ] ].kind ));

  if( FD_UNLIKELY( tile->out_cnt != 2 ||
                   topo->links[ tile->out_link_id[ NET_OUT_IDX ] ].kind != FD_TOPO_LINK_KIND_SHRED_TO_NETMUX  ||
                   topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ].kind != FD_TOPO_LINK_KIND_SHRED_TO_SIGN ) )
    FD_LOG_ERR(( "shred tile has none or unexpected output links %lu %lu %lu",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].kind, topo->links[ tile->out_link_id[ 1 ] ].kind ));

  ulong shred_store_mcache_depth = tile->shred.depth;
  if( topo->links[ tile->out_link_id_primary ].depth != shred_store_mcache_depth )
    FD_LOG_ERR(( "shred tile in depths are not equal" ));

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "shred tile has no primary output link" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_ip_align(), fd_ip_footprint( 256UL, 256UL ) );

  ulong fec_resolver_footprint = fd_fec_resolver_footprint( tile->shred.fec_resolver_depth, 1UL, shred_store_mcache_depth,
                                                            128UL * tile->shred.fec_resolver_depth );
  ulong fec_set_cnt            = shred_store_mcache_depth + tile->shred.fec_resolver_depth + 4UL;

  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) ) FD_LOG_ERR(( "shred tile has no primary output link" ));
  void * store_out_dcache = topo->links[ tile->out_link_id_primary ].dcache;

  ulong required_dcache_sz = fec_set_cnt*DCACHE_ENTRIES_PER_FEC_SET*sizeof(fd_shred34_t);
  if( fd_dcache_data_sz( store_out_dcache )<required_dcache_sz ) {
    FD_LOG_ERR(( "shred->store dcache too small. It is %lu bytes but must be at least %lu bytes.",
                 fd_dcache_data_sz( store_out_dcache ),
                 required_dcache_sz ));
  }

  if( FD_UNLIKELY( !tile->shred.fec_resolver_depth ) ) FD_LOG_ERR(( "fec_resolver_depth not set" ));

  uchar zero_mac_addr[6] = {0};
  if( FD_UNLIKELY( fd_memeq( tile->shred.src_mac_addr, zero_mac_addr, sizeof(zero_mac_addr ) ) ) ) FD_LOG_ERR(( "src_mac_addr not set" ));
  if( FD_UNLIKELY( !tile->shred.ip_addr ) ) FD_LOG_ERR(( "ip_addr not set" ));
  if( FD_UNLIKELY( !tile->shred.shred_listen_port ) ) FD_LOG_ERR(( "shred_listen_port not set" ));

  ulong bank_cnt = fd_topo_tile_kind_cnt( topo, FD_TOPO_TILE_KIND_BANK );
  if( FD_UNLIKELY( !bank_cnt ) ) FD_LOG_ERR(( "0 bank tiles" ));
  if( FD_UNLIKELY( bank_cnt>MAX_BANK_CNT ) ) FD_LOG_ERR(( "Too many banks" ));

  void * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),              fd_stake_ci_footprint()            );
  void * _resolver = FD_SCRATCH_ALLOC_APPEND( l, fd_fec_resolver_align(),          fec_resolver_footprint             );
  void * _shredder = FD_SCRATCH_ALLOC_APPEND( l, fd_shredder_align(),              fd_shredder_footprint()            );
  void * _fec_sets = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fec_set_t),            sizeof(fd_fec_set_t)*fec_set_cnt   );

  fd_fec_set_t * fec_sets = (fd_fec_set_t *)_fec_sets;
  fd_shred34_t * shred34  = (fd_shred34_t *)store_out_dcache;

  for( ulong i=0UL; i<fec_set_cnt; i++ ) {
    fd_shred34_t * p34_base = shred34 + i*DCACHE_ENTRIES_PER_FEC_SET;
    for( ulong k=0UL; k<DCACHE_ENTRIES_PER_FEC_SET; k++ ) {
      fd_shred34_t * p34 = p34_base + k;

      p34->stride   = (ulong)p34->pkts[1].buffer - (ulong)p34->pkts[0].buffer;
      p34->offset   = (ulong)p34->pkts[0].buffer - (ulong)p34;
      p34->shred_sz = fd_ulong_if( k<2UL, 1203UL, 1228UL );
    }

    uchar ** data_shred   = fec_sets[ i ].data_shreds;
    uchar ** parity_shred = fec_sets[ i ].parity_shreds;
    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) data_shred  [ j ] = p34_base[       j/34UL ].pkts[ j%34UL ].buffer;
    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) parity_shred[ j ] = p34_base[ 2UL + j/34UL ].pkts[ j%34UL ].buffer;
  }

#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  ulong expected_shred_version = tile->shred.expected_shred_version;
  if( FD_LIKELY( !expected_shred_version ) ) {
    ulong * gossip_shred_version = (ulong*)tile->extra[0];
    FD_LOG_INFO(( "Waiting for shred version to be determined via gossip." ));
    while( !expected_shred_version ) {
      expected_shred_version = FD_VOLATILE_CONST( *gossip_shred_version );
    }
  }

  if( FD_UNLIKELY( expected_shred_version > USHORT_MAX ) ) FD_LOG_ERR(( "invalid shred version %lu", expected_shred_version ));
  FD_LOG_INFO(( "Using shred version %hu", (ushort)expected_shred_version ));

  /* populate ctx */
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ SIGN_IN_IDX ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];
  NONNULL( fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
                                                            sign_out->mcache,
                                                            sign_out->dcache,
                                                            sign_in->mcache,
                                                            sign_in->dcache ) ) );

  fd_fec_set_t * resolver_sets = fec_sets + (shred_store_mcache_depth+1UL)/2UL + 1UL;
  ctx->shredder = NONNULL( fd_shredder_join     ( fd_shredder_new     ( _shredder, fd_shred_signer, ctx->keyguard_client, (ushort)expected_shred_version ) ) );
  ctx->resolver = NONNULL( fd_fec_resolver_join ( fd_fec_resolver_new ( _resolver, tile->shred.fec_resolver_depth, 1UL,
                                                                         (shred_store_mcache_depth+3UL)/2UL,
                                                                         128UL * tile->shred.fec_resolver_depth, resolver_sets ) )         );

  ctx->shred34  = shred34;
  ctx->fec_sets = fec_sets;

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, ctx->identity_key ) );

  ctx->net_id   = (ushort)0;

  populate_packet_header_template( ctx->data_shred_net_hdr,   FD_SHRED_MIN_SZ, tile->shred.ip_addr, tile->shred.src_mac_addr, tile->shred.shred_listen_port );
  populate_packet_header_template( ctx->parity_shred_net_hdr, FD_SHRED_MAX_SZ, tile->shred.ip_addr, tile->shred.src_mac_addr, tile->shred.shred_listen_port );

  fd_topo_link_t * netmux_shred_link = &topo->links[ tile->in_link_id[ NET_IN_IDX     ] ];
  fd_topo_link_t * poh_shred_link    = &topo->links[ tile->in_link_id[ POH_IN_IDX     ] ];
  fd_topo_link_t * stake_in_link     = &topo->links[ tile->in_link_id[ STAKE_IN_IDX   ] ];
  fd_topo_link_t * contact_in_link   = &topo->links[ tile->in_link_id[ CONTACT_IN_IDX ] ];

  /* The networking in mcache contains frags from several dcaches, so
     use the entire wksp data region as the chunk bounds. */
  ctx->net_in_mem    = topo->workspaces[ netmux_shred_link->wksp_id ].wksp;
  ctx->net_in_chunk0 = fd_disco_compact_chunk0( ctx->net_in_mem );
  ctx->net_in_wmark  = fd_disco_compact_wmark ( ctx->net_in_mem, netmux_shred_link->mtu );

  ctx->poh_in_mem    = topo->workspaces[ poh_shred_link->wksp_id ].wksp;
  ctx->poh_in_chunk0 = fd_dcache_compact_chunk0( ctx->poh_in_mem, poh_shred_link->dcache );
  ctx->poh_in_wmark  = fd_dcache_compact_wmark ( ctx->poh_in_mem, poh_shred_link->dcache, poh_shred_link->mtu );

  ctx->stake_in_mem    = topo->workspaces[ stake_in_link->wksp_id ].wksp;
  ctx->stake_in_chunk0 = fd_dcache_compact_chunk0( ctx->stake_in_mem, stake_in_link->dcache );
  ctx->stake_in_wmark  = fd_dcache_compact_wmark ( ctx->stake_in_mem, stake_in_link->dcache, stake_in_link->mtu );

  ctx->contact_in_mem    = topo->workspaces[ contact_in_link->wksp_id ].wksp;
  ctx->contact_in_chunk0 = fd_dcache_compact_chunk0( ctx->contact_in_mem, contact_in_link->dcache );
  ctx->contact_in_wmark  = fd_dcache_compact_wmark ( ctx->contact_in_mem, contact_in_link->dcache, contact_in_link->mtu );

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ 0 ] ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ net_out->wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_topo_link_t * store_out = &topo->links[ tile->out_link_id_primary ];

  ctx->store_out_mem    = topo->workspaces[ store_out->wksp_id ].wksp;
  ctx->store_out_chunk0 = fd_dcache_compact_chunk0( ctx->store_out_mem, store_out->dcache );
  ctx->store_out_wmark  = fd_dcache_compact_wmark ( ctx->store_out_mem, store_out->dcache, store_out->mtu );
  ctx->store_out_chunk  = ctx->store_out_chunk0;

  ctx->shredder_fec_set_idx = 0UL;
  ctx->shredder_max_fec_set_idx = (shred_store_mcache_depth+1UL)/2UL + 1UL;

  ctx->send_fec_set_idx    = ULONG_MAX;

  ctx->shred_buffer_sz  = 0UL;
  fd_memset( ctx->shred_buffer, 0xFF, FD_NET_MTU );

  ctx->src_ip_addr = tile->shred.ip_addr;
  fd_memcpy( ctx->src_mac_addr, tile->shred.src_mac_addr, 6UL );
  ctx->shred_listen_port = tile->shred.shred_listen_port;

  ctx->pending_batch.microblock_cnt = 0UL;
  ctx->pending_batch.pos            = 0UL;
  ctx->pending_batch.slot           = 0UL;
  fd_memset( ctx->pending_batch.payload, 0, sizeof(ctx->pending_batch.payload) );

  fd_ip_arp_fetch( ctx->ip );
  fd_ip_route_fetch( ctx->ip );
  warmup_arp_cache( ctx );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  int netlink_fd = fd_ip_netlink_get( ctx->ip )->fd;
  FD_TEST( netlink_fd >= 0 );
  populate_sock_filter_policy_shred( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)netlink_fd );
  return sock_filter_policy_shred_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_shred_ctx_t ), sizeof( fd_shred_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt < 3 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_ip_netlink_get( ctx->ip )->fd; /* netlink socket */
  return out_cnt;
}

fd_tile_config_t fd_tile_shred = {
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 4UL,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
