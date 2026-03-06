/* fd_rserve_tile serves incoming repair requests from other nodes */

#include "fd_rserve.h"
#include "fd_repair.h"
#include "generated/fd_rserve_tile_seccomp.h"
#include "../../disco/fd_disco_base.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyguard.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/shred/fd_fec_set.h"
#include "../../disco/store/fd_shredb.h"
#include "../../disco/store/fd_store.h"
#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../util/net/fd_net_headers.h"
#include "../../util/pod/fd_pod.h"

#define IN_KIND_NET    (0)
#define IN_KIND_SHRED  (1)
#define IN_KIND_SIGN   (2)

#define MAX_IN_LINKS 32

#define FD_RSERVE_MAX_PACKET_SIZE 1232

/* The maximum number of parent slots to look for. */
#define FD_RSERVE_MAX_OPRHAN_SLOTS 11

/* 10 minutes in milliseconds. */
#define FD_RSERVE_SIGNED_REPAIR_WINDOW (60L*10L*1000L)

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  };
  fd_net_rx_bounds_t net_rx;
} in_ctx_t;

typedef struct ctx {
  fd_net_rx_bounds_t net_rx;

  uint     in_kind [ MAX_IN_LINKS ];
  in_ctx_t in_links[ MAX_IN_LINKS ];

  uint        net_out_idx;
  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  uint        shred_out_idx;
  fd_wksp_t * shred_out_mem;
  ulong       shred_out_chunk0;
  ulong       shred_out_wmark;
  ulong       shred_out_chunk;

  ulong         seed;
  fd_rserve_t * rserve;
  fd_shredb_t * shredb;
  fd_store_t  * store;

  /* Used for verifying incoming requests, and signing outgoing responses. */
  fd_sha512_t sha512[1];
  fd_keyguard_client_t keyguard_client[1];
  fd_keyswitch_t * keyswitch;
  fd_pubkey_t identity_public_key;
  int halt_signing;

  fd_ip4_udp_hdrs_t serve_hdr[1];
  ushort            net_id;

} ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(ctx_t),    sizeof(ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_shredb_align(), fd_shredb_footprint( tile->rserve.shred_storage_limit_gib ) );
  l = FD_LAYOUT_APPEND( l, fd_rserve_align(), fd_rserve_footprint( tile->rserve.ping_cache_entries) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
send_packet( ctx_t               * ctx,
            fd_stem_context_t    * stem,
            uint                   dst_ip_addr,
            ushort                 dst_port,
            uint                   src_ip_addr,
            uchar const          * payload,
            ulong                  payload_sz,
            ulong                  tsorig ) {
  uchar * packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *ctx->serve_hdr;

  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->saddr       = src_ip_addr;
  ip4->daddr       = dst_ip_addr;
  ip4->net_id      = fd_ushort_bswap( ctx->net_id++ );
  ip4->check       = 0U;
  ip4->net_tot_len = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t)) );
  ip4->check       = fd_ip4_hdr_check_fast( ip4 );

  fd_udp_hdr_t * udp = hdr->udp;
  udp->net_dport = dst_port;
  udp->net_len   = fd_ushort_bswap( (ushort)(payload_sz + sizeof(fd_udp_hdr_t)) );
  fd_memcpy( packet+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz );
  hdr->udp->check = 0U;

  ulong tspub     = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig       = fd_disco_netmux_sig( dst_ip_addr, dst_port, dst_ip_addr, DST_PROTO_OUTGOING, sizeof(fd_ip4_udp_hdrs_t) );
  ulong packet_sz = payload_sz + sizeof(fd_ip4_udp_hdrs_t);
  ulong chunk     = ctx->net_out_chunk;
  fd_stem_publish( stem, ctx->net_out_idx, sig, chunk, packet_sz, 0UL, tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );
}

static inline void
handle_pong( ctx_t              * ctx,
             uchar const        * payload,
             ulong                payload_sz,
             ulong                tsorig ) {
  if( FD_UNLIKELY( payload_sz!=132UL ) ) return;
  fd_repair_msg_t const * msg = (fd_repair_msg_t const *)payload;
  fd_repair_pong_t const * request = &msg->pong;

  if( FD_UNLIKELY( fd_pubkey_eq( &ctx->identity_public_key, &request->from ) ) ) {
    /* We've received our own repair request, ignore. */
    return;
  }

  if( FD_UNLIKELY( FD_ED25519_SIG_SZ!=fd_ed25519_verify( request->hash.uc, 32UL, request->sig, request->from.uc, ctx->sha512 ) ) ) {
    /* Invalid signature, ignore. */
    return;
  }

  ping_cache_entry_t * entry = ping_cache_query( ctx->rserve->ping_cache, request->from, NULL );
  /* If it doesn't exist yet, create the entry. */
  if( FD_LIKELY( !entry ) ) {
    entry = ping_cache_insert( ctx->rserve->ping_cache, request->from );
  }
  /* It must have either already existed, or we just created it.
     insert() may only fail if the key already existed .*/
  FD_TEST( entry );

  /* Update the timestmap. */
  entry->timestamp = tsorig;

  /* Now the sender must re-send their request, but this time we'll have their ping cache entry. */
  return;
}

static inline void
handle_net_request( ctx_t             * ctx,
                    fd_stem_context_t * stem,
                    uchar const       * payload,
                    ulong               payload_sz,
                    fd_udp_hdr_t      * udp,
                    fd_ip4_hdr_t      * ip4,
                    ulong               tsorig ) {
  if( FD_UNLIKELY( payload_sz<4UL ) ) return;
  uint tag = FD_LOAD( uint, payload );

  if( FD_UNLIKELY( tag==FD_REPAIR_KIND_PONG ) ) {
    handle_pong( ctx, payload, payload_sz, tsorig );
    return;
  }
  if( FD_UNLIKELY( tag!=FD_REPAIR_KIND_SHRED &&
                   tag!=FD_REPAIR_KIND_HIGHEST_SHRED &&
                   tag!=FD_REPAIR_KIND_ORPHAN ) ) {
    return;
  }

  /* The Window, HighestWindow, and Orphan requests all start with:
     - tag         (4 bytes)
     - signature   (64 bytes)
     - from pubkey (32 bytes)
     - to pubkey   (32 bytes)
     - timestamp   (8 bytes)
     - nonce       (4 bytes)
     which adds up to at least 144 bytes. */
  if( FD_UNLIKELY( payload_sz<144UL ) ) return;
  fd_repair_msg_t const * msg = (fd_repair_msg_t const *)payload;
  fd_repair_req_header_t const * header = &msg->header;

  if( FD_UNLIKELY( !fd_pubkey_eq( &ctx->identity_public_key, &header->to ) ) ) {
    /* The message wasn't intended for us, ignore. */
    return;
  }
  if( FD_UNLIKELY( fd_pubkey_eq( &ctx->identity_public_key, &header->from ) ) ) {
    /* We've received our own repair request, ignore. */
    return;
  }

  long current = FD_NANOSEC_TO_MILLI( fd_log_wallclock() );
  if( FD_UNLIKELY( current-(long)header->ts > FD_RSERVE_SIGNED_REPAIR_WINDOW ) ) {
    /* The message was sent too long ago, ignore. */
    return;
  }

  /* Verify the signature. */

  /* The largest signable payload size is 96 bytes, that being
     160-64=96, as the signature itself is not included. */
  uchar signable[ 96 ];
  uchar signable_sz = tag==FD_REPAIR_KIND_ORPHAN ? 88 : 96;
  fd_memcpy( signable,     payload,      4             );
  fd_memcpy( signable+4UL, payload+68UL, signable_sz-4 );

  if( FD_UNLIKELY( FD_ED25519_SIG_SZ!=fd_ed25519_verify( signable, signable_sz, header->sig, header->from.uc, ctx->sha512 ) ) ) {
    /* Invalid signature, ignore. */
    return;
  }

  /* Check whether we've heard a pong response from them. */
  ping_cache_entry_t * entry = ping_cache_query( ctx->rserve->ping_cache, header->from, NULL );
  if( FD_LIKELY( entry ) ) {
    switch( tag ) {
      case FD_REPAIR_KIND_SHRED:
      case FD_REPAIR_KIND_HIGHEST_SHRED: {
        ulong slot = msg->shred.slot;
        ulong shred_idx = msg->shred.shred_idx;

        if( FD_UNLIKELY( (shred_idx & fd_ulong_mask( 15, 64 ) )!=0 ) ) {
          /* If the shred_idx does not fit into 15-bits, reject it. */
          return;
        }

        uchar payload[ FD_SHRED_MAX_SZ+sizeof(uint) ];
        int len;
        if( tag==FD_REPAIR_KIND_SHRED ) {
          len = fd_shredb_query( ctx->shredb, slot, (uint)shred_idx, payload );
        } else {
          len = fd_shredb_query_highest( ctx->shredb, slot, (uint)shred_idx, payload );
        }
        if( FD_UNLIKELY( len<0 ) ) {
          FD_LOG_NOTICE(("didn't have shreds for (slot=%lu, shred_idx=%lu)", slot, shred_idx ));
          return;
        }

        FD_LOG_NOTICE(( "found shreds for (slot=%lu, shred_idx=%lu, sz=%d)", slot, shred_idx, len ));

        fd_memcpy( payload+len, &header->nonce, sizeof(uint) );
        send_packet( ctx, stem, ip4->saddr, udp->net_sport, ip4->daddr, payload, (ulong)len+sizeof(uint), fd_frag_meta_ts_comp( fd_tickcount() ) );
        return;
      }
      case FD_REPAIR_KIND_ORPHAN: {
        /* Orphan repair works by giving us a "root" slot to start at,
           and has us walk back through the parent slots sending the
           highest shred of each slot.
           We may send up to FD_RSERVE_MAX_OPRHAN_SLOTS of these shreds
           (including the root one). */
        fd_repair_orphan_req_t const * request = &msg->orphan;
        ulong current = request->slot;
        for( uint i=0; i<FD_RSERVE_MAX_OPRHAN_SLOTS; i++ ) {
          uchar payload[ FD_SHRED_MAX_SZ+sizeof(uint) ];
          int len = fd_shredb_query_highest( ctx->shredb, current, 0, payload );
          if( FD_UNLIKELY( len<0 ) ) {
            FD_LOG_NOTICE(("didn't have orphan shreds for (slot=%lu, root=%lu)", current, request->slot ));
            return;
          }
          fd_shred_t const * shred = (fd_shred_t const *)fd_type_pun_const( payload );
          send_packet( ctx, stem, ip4->saddr, udp->net_sport, ip4->daddr, payload, (ulong)len+sizeof(uint), fd_frag_meta_ts_comp( fd_tickcount() ) );
          /* fd_shred_parse ensures that parent_off will be 0 if slot is 0 */
          current = request->slot - shred->data.parent_off;
        }
        break;
      }
    }
  } else {
    /* Generate a token. */
    uchar token[ 32 ];
    fd_memcpy( token,    "SOLANA_PING_PONG", 16 );
    fd_memset( token+16, 0xAA,               16 ); /* TODO: generate real token */

    /* Sign the token. */
    uchar signature[ 64UL ];
    fd_keyguard_client_sign( ctx->keyguard_client, signature, token, 32UL, FD_KEYGUARD_SIGN_TYPE_ED25519 );

    fd_repair_ping_t msg[ 1 ];
    msg->kind = FD_REPAIR_KIND_PING;
    msg->ping.from = ctx->identity_public_key;
    fd_memcpy( msg->ping.sig, signature, 64 );

    /* Send the ping packet back to the source. */
    send_packet( ctx, stem, ip4->saddr, udp->net_sport, ip4->daddr, (uchar const *)fd_type_pun_const( msg ), sizeof(fd_repair_ping_t), fd_frag_meta_ts_comp( fd_tickcount() ) );
  }
}

static inline void
handle_shred( ctx_t             * ctx,
              uchar const       * payload,
              ulong               sig ) {
  /* The shred_out link only sends along the shred headers, so we must
     store headers first and then fill in the payload.

     1. The shred tile will send any data shred headers it receives, while
        storing the payloads internally.

     2. Once the shred tile has the full FEC set, it will push any data
        shreds that were recovered, instead of received externally. This
        ensures that we must have seen every data shred header from the
        set before we see the "complete" FD_SHRED_OUT_MSG_TYPE_FEC message.

     3. When we see the FD_SHRED_OUT_MSG_TYPE_FEC message, we know that
        the store must contain the fully assembled FEC set, and query it
        with the merkle root of the last shred.

        Afterwards, since we know that we've seen every data shred header
        before the last one for the set, we will iterate "backwards", going
        from the last to the first shred, inserting the payloads that were
        stored in the fd_store. This completes the store entry, which now
        contain full shreds. */
  fd_shred_t const * shred = (fd_shred_t const *)fd_type_pun_const( payload );
  switch( fd_disco_shred_out_msg_type( sig ) ) {
    case FD_SHRED_OUT_MSG_TYPE_SHRED: {
      /* Record the shred's header. The shred_out link doesn't contain the
         full shred payload, we will get that once the full FEC set has been
         completed. */
      fd_shredb_insert_header( ctx->shredb, shred );
      return;
    }
    case FD_SHRED_OUT_MSG_TYPE_FEC: {
      ulong slot = shred->slot;
      fd_hash_t const * mr = (fd_hash_t const *)fd_type_pun_const( payload + FD_SHRED_DATA_HEADER_SZ );

      uint offsets[ 32 ];
      uchar data[ FD_STORE_DATA_MAX ];

      FD_STORE_SLOCK_BEGIN( ctx->store ) {
        fd_store_fec_t const * set = fd_store_query( ctx->store, mr );
        if( FD_UNLIKELY( !set ) ) {
          /* Something bad must have happened, and the rserve process was
             stalled for long enough that the replay tile has removed the
             entry from the store.

             This brings up some questions regarding liveness, and if enough
             stake behaves in a similar manner it is possible certain blocks
             become un-repairable, but for now we will simply log a
             metric/warning and move on. It is valid for us to not have the
             requested shred.

             TODO: There are several solutions possible to mitigate this,
             such as reference counting the store entries or structuring the
             pipeline in a way where the repair server is guarnteed to have
             read the entry before replay is allowed to remove it. */
          FD_LOG_WARNING(( "store query not found (slot=%lu, shred_idx=%u)", slot, shred->idx ));
          return;
        }
        fd_memcpy( offsets, set->block_offs, sizeof(uint)*32 );
        fd_memcpy( data,    set->data,       set->data_sz    );
      } FD_STORE_SLOCK_END;

      /* Insert the last shred header, which we have just received. */
      fd_shredb_insert_header( ctx->shredb, shred );

      for( uint i=0; i<FD_FEC_SHRED_CNT; i++ ) {
        uint shred_idx = shred->idx - i; /* Computed shred index of the previously inserted shreds. */
        ulong payload_sz = i==0  ? offsets[ 0 ] : (offsets[ i ] - offsets[ i - 1 ]);
        uchar const * payload = data+offsets[ i ];
        fd_shredb_insert_payload( ctx->shredb, payload, payload_sz, slot, shred_idx );
      }
      return;
    }
    default: FD_LOG_ERR(( "unknown shred message type: %d", fd_disco_shred_out_msg_type( sig ) ));
  }
}

static inline int
returnable_frag( ctx_t             * ctx,
                 ulong               in_idx,
                 ulong               seq FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  uint in_kind = ctx->in_kind[ in_idx ];
  in_ctx_t const * in_ctx = &ctx->in_links[ in_idx ];

  switch( in_kind ) {
  case IN_KIND_NET: {
    if( FD_UNLIKELY( ctx->halt_signing ) ) return 1;
    if( fd_disco_netmux_sig_proto( sig )!=DST_PROTO_RSERVE ) return 0;

    uchar const * buffer = fd_net_rx_translate_frag( &in_ctx->net_rx, chunk, ctl, sz );
    uchar * payload; ulong payload_sz;
    fd_udp_hdr_t * udp;
    fd_ip4_hdr_t * ip4;
    if( FD_UNLIKELY( !fd_ip4_udp_hdr_strip( buffer, sz, &payload, &payload_sz, NULL, &ip4, &udp ) ) ) {
      FD_LOG_WARNING(( "rserve: malformed packet (sz=%lu)", sz ));
      return 0;
    }
    handle_net_request( ctx, stem, payload, payload_sz, udp, ip4, tsorig );
    return 0;
  }
  case IN_KIND_SHRED: {
    if( FD_UNLIKELY( sz==0UL ) ) return 0;
    if( FD_UNLIKELY( chunk<in_ctx->chunk0 || chunk>in_ctx->wmark || sz>in_ctx->mtu ) )
      FD_LOG_ERR(( "chunk %lu %lu from in %u corrupt, not in range [%lu,%lu]", chunk, sz, in_kind, in_ctx->chunk0, in_ctx->wmark ));

    uchar const * buffer = fd_chunk_to_laddr_const( in_ctx->mem, chunk );
    handle_shred( ctx, buffer, sig );
    return 0;
  }
  default: FD_LOG_ERR(( "unexpected input kind (%u)", in_kind ));
  }
}

static inline void
during_housekeeping( ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
    FD_LOG_DEBUG(( "keyswitch: unhalting" ));
    FD_CRIT( ctx->halt_signing, "state machine corruption" );
    fd_memcpy( ctx->identity_public_key.uc, ctx->keyswitch->bytes, sizeof(fd_pubkey_t) );
    ctx->halt_signing = 0;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    ctx->halt_signing = 1;
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
privileged_init( fd_topo_t *      topo,
                fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong size_limit = tile->rserve.shred_storage_limit_gib;
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),    sizeof(ctx_t)                     );
  ctx->shredb = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_align(), fd_shredb_footprint( size_limit ) );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ulong) ) );

  FD_LOG_NOTICE(( "creating shredb (size_limit=%luGiB)", size_limit ));
  ctx->shredb = fd_shredb_join( fd_shredb_new( ctx->shredb, size_limit, tile->rserve.shredb_path, ctx->seed ) );
  if( FD_UNLIKELY( !ctx->shredb ) ) FD_LOG_ERR(( "failed to initialize shredb" ));

  uchar const * identity_public_key = fd_keyload_load( tile->repair.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_public_key.uc, identity_public_key, sizeof(fd_pubkey_t) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                  fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong ping_cache_entries = tile->rserve.ping_cache_entries;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),    sizeof(ctx_t) );
                FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_align(), fd_shredb_footprint( tile->rserve.shred_storage_limit_gib ) );
  ctx->rserve = FD_SCRATCH_ALLOC_APPEND( l, fd_rserve_align(), fd_rserve_footprint( ping_cache_entries ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, scratch_align() )==(ulong)scratch + scratch_footprint( tile ) );

  (void)ctx->shredb; /* Initialized in privileged_init */
  ctx->rserve    = fd_rserve_join   ( fd_rserve_new( ctx->rserve, ping_cache_entries, ctx->seed ) );
  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  ctx->halt_signing = 0;
  ctx->net_id = (ushort)0;
  fd_ip4_udp_hdr_init( ctx->serve_hdr, FD_RSERVE_MAX_PACKET_SIZE, 0, tile->rserve.repair_serve_listen_port );
  fd_sha512_new( ctx->sha512 );

  ulong sign_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "sign_rserve", tile->kind_id );
  ulong sign_out_idx = fd_topo_find_tile_out_link( topo, tile, "rserve_sign", tile->kind_id );
  FD_TEST( sign_in_idx!=ULONG_MAX );
  fd_topo_link_t * sign_in = &topo->links[ tile->in_link_id[ sign_in_idx ] ];
  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ sign_out_idx ] ];
  if( FD_UNLIKELY( !fd_keyguard_client_join( fd_keyguard_client_new( ctx->keyguard_client,
          sign_out->mcache,
          sign_out->dcache,
          sign_in->mcache,
          sign_in->dcache,
          sign_out->mtu ) ) ) ) {
    FD_LOG_ERR(( "failed to construct keyguard" ));
  }

  FD_TEST( tile->in_cnt>=1UL );
  for( ulong in_idx=0UL; in_idx<tile->in_cnt; in_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ in_idx ] ];
    if( 0==strcmp( link->name, "net_rserve" ) ) {
      ctx->in_kind[ in_idx ] = IN_KIND_NET;
      fd_net_rx_bounds_init( &ctx->in_links[ in_idx ].net_rx, link->dcache );
      continue;
    }
    else if( 0==strcmp( link->name, "shred_out"   ) ) ctx->in_kind[ in_idx ] = IN_KIND_SHRED;
    else if( 0==strcmp( link->name, "sign_rserve" ) ) ctx->in_kind[ in_idx ] = IN_KIND_SIGN;
    else FD_LOG_ERR(( "rserve tile has unexpected input link: %s", link->name ));

    ctx->in_links[ in_idx ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in_links[ in_idx ].chunk0 = fd_dcache_compact_chunk0( ctx->in_links[ in_idx ].mem, link->dcache );
    ctx->in_links[ in_idx ].wmark  = fd_dcache_compact_wmark ( ctx->in_links[ in_idx ].mem, link->dcache, link->mtu );
    ctx->in_links[ in_idx ].mtu    = link->mtu;
  }

  ctx->net_out_idx = UINT_MAX;
  for( uint out_idx=0U; out_idx<tile->out_cnt; out_idx++ ) {
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ out_idx ] ];
    if( 0==strcmp( link->name, "rserve_net" ) ) {
      if( ctx->net_out_idx!=UINT_MAX ) continue; /* only use the first net link */
      ctx->net_out_idx    = out_idx;
      ctx->net_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->net_out_chunk0 = fd_dcache_compact_chunk0( ctx->net_out_mem, link->dcache );
      ctx->net_out_wmark  = fd_dcache_compact_wmark( ctx->net_out_mem, link->dcache, link->mtu );
      ctx->net_out_chunk  = ctx->net_out_chunk0;
    }
    else if( 0==strcmp( link->name, "rserve_sign" ) ) { /* Handled above for keyguard. */ }
    else FD_LOG_ERR(( "rserve tile has unexpected output link: %s", link->name ));
  }
  if( FD_UNLIKELY( ctx->net_out_idx==UINT_MAX ) ) FD_LOG_ERR(( "Missing rserve_net output link" ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );
  populate_sock_filter_policy_fd_rserve_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->shredb->fd );
  return sock_filter_policy_fd_rserve_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->shredb->fd;
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY (64000UL)

#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_rserve = {
  .name                     = "rserve",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
