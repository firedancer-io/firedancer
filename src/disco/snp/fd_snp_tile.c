#include "../tiles.h"

#include "generated/fd_snp_tile_seccomp.h"
#include "../shred/fd_shred_dest.h"
#include "../shred/fd_stake_ci.h"
#include "../keyguard/fd_keyload.h"
#include "../keyguard/fd_keyguard.h"
#include "../keyguard/fd_keyswitch.h"
#include "../fd_disco.h"
#include "../net/fd_net_tile.h"
#include "../../waltz/snp/fd_snp.h"
#include "../../waltz/snp/fd_snp_app.h"

#include <linux/unistd.h>

#include "../../app/fdctl/version.h"

static inline fd_snp_limits_t
snp_limits( fd_topo_tile_t const * tile ) {
  (void)tile;
  fd_snp_limits_t limits = {
    .peer_cnt = 65536, /* >= MAX_SHRED_DESTS, power of 2 */
  };
  if( FD_UNLIKELY( !fd_snp_footprint( &limits ) ) ) {
    FD_LOG_ERR(( "Invalid SNP limits in config" ));
  }
  return limits;
}

#define FD_SNP_TILE_SCRATCH_ALIGN (128UL)

#define IN_KIND_NET_SHRED   (0UL)
#define IN_KIND_SHRED       (1UL)
#define IN_KIND_GOSSIP      (2UL)
#define IN_KIND_SIGN        (3UL)
#define IN_KIND_CRDS        (4UL)
#define IN_KIND_STAKE       (5UL)

/* The order here depends on the order in which fd_topob_tile_out(...)
    are called inside topology.c (in the corresponding folder) */
#define NET_OUT_IDX      (0)
#define SHRED_OUT_IDX    (1)
#define SIGN_OUT_IDX     (2)

#define SNP_MIN_FDCTL_MINOR_VERSION (711)

typedef union {
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  };
  fd_net_rx_bounds_t net_rx;
} fd_snp_in_ctx_t;

typedef struct {

  fd_pubkey_t      identity_key[1]; /* Just the public key */

  int              skip_frag;
  ulong            round_robin_id;
  ulong            round_robin_cnt;

  fd_keyswitch_t * keyswitch;

  fd_stake_ci_t  * stake_ci;
  /* These are used in between during_frag and after_frag */
  fd_shred_dest_weighted_t * new_dest_ptr;
  ulong                      new_dest_cnt;

  fd_snp_in_ctx_t  in[ 32 ];
  int              in_kind[ 32 ];

  /* Channels */
  fd_wksp_t *      net_out_mem;
  ulong            net_out_chunk0;
  ulong            net_out_wmark;
  ulong            net_out_chunk;

  fd_wksp_t *      shred_out_mem;
  ulong            shred_out_chunk0;
  ulong            shred_out_wmark;
  ulong            shred_out_chunk;

  fd_wksp_t *      sign_out_mem;
  ulong            sign_out_chunk0;
  ulong            sign_out_wmark;
  ulong            sign_out_chunk;

  uchar            signature[ FD_ED25519_SIG_SZ ];

  /* SNP */
  uchar *          packet;
  ulong            packet_sz;
  fd_snp_t *       snp;

  /* SNP enforced destinations */
  ulong            enforced_cnt;
  ulong            enforced[ FD_TOPO_ADTL_DESTS_MAX ];

  /* App-specific */
  ulong            shred_cnt;

  fd_stem_context_t * stem;

  fd_snp_app_t * snp_app;

  fd_snp_meta_t meta;
  ulong         sig;
  ulong         tsorig;
} fd_snp_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return FD_SNP_TILE_SCRATCH_ALIGN;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_snp_limits_t limits = snp_limits( tile );
  fd_snp_app_limits_t limits_app = {0};

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snp_tile_ctx_t), sizeof(fd_snp_tile_ctx_t)           );
  l = FD_LAYOUT_APPEND( l, fd_stake_ci_align(),        fd_stake_ci_footprint()             );
  l = FD_LAYOUT_APPEND( l, fd_snp_align(),             fd_snp_footprint( &limits )         );
  l = FD_LAYOUT_APPEND( l, fd_snp_app_align(),         fd_snp_app_footprint( &limits_app ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_snp_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_memcpy( ctx->identity_key->uc, ctx->keyswitch->bytes, 32UL );
    fd_stake_ci_set_identity( ctx->stake_ci, ctx->identity_key );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );

    fd_snp_set_identity( ctx->snp, ctx->identity_key->uc );
  }

  /* SNP housekeeping */
  fd_snp_housekeeping( ctx->snp );

#if FD_SNP_DEBUG_ENABLED
  /* SNP logged metrics. */
  static long snp_next_metrics_log = 0L;
  long now = fd_snp_timestamp_ms();
  if( now > snp_next_metrics_log ) {
    FD_LOG_NOTICE(( "[SNP] contacts=%lu connections=%lu", fd_snp_dest_meta_map_key_cnt( ctx->snp->dest_meta_map ), fd_snp_conn_pool_used( ctx->snp->conn_pool ) ));
    snp_next_metrics_log = now + 10000L; /* Every 10 seconds. */
  }
#endif
}

static inline void
handle_new_cluster_contact_info( fd_snp_tile_ctx_t * ctx,
                                 uchar const *       buf ) {

  ulong const * header = (ulong const *)fd_type_pun_const( buf );

  ulong dest_cnt = header[ 0 ];
  if( dest_cnt >= MAX_SHRED_DESTS )
    FD_LOG_ERR(( "Cluster nodes had %lu destinations, which was more than the max of %lu", dest_cnt, MAX_SHRED_DESTS ));

  fd_shred_dest_wire_t const * in_dests = fd_type_pun_const( header+1UL );
  fd_shred_dest_weighted_t * dests = fd_stake_ci_dest_add_init( ctx->stake_ci );

  ctx->new_dest_ptr = dests;
  ctx->new_dest_cnt = dest_cnt;

  ctx->snp->dest_meta_update_idx += 1U;

  for( ulong i=0UL; i<dest_cnt; i++ ) {
    memcpy( dests[i].pubkey.uc, in_dests[i].pubkey, 32UL );
    uint   ip4_addr = in_dests[i].ip4_addr;
    ushort udp_port = in_dests[i].udp_port;

    dests[i].ip4  = ip4_addr;
    dests[i].port = udp_port;

    uchar snp_available = (in_dests[i].version_minor >= SNP_MIN_FDCTL_MINOR_VERSION) ? 1U : 0U;

    ulong key = fd_snp_dest_meta_map_key_from_parts( ip4_addr, udp_port );
    fd_snp_dest_meta_map_t sentinel = { 0 };
    fd_snp_dest_meta_map_t * entry = fd_snp_dest_meta_map_query( ctx->snp->dest_meta_map, key, &sentinel );

    int is_new = 0;
    if( FD_UNLIKELY( !entry->key ) ) {
      entry = fd_snp_dest_meta_map_insert( ctx->snp->dest_meta_map, key );
      if( !entry ) continue;
      memset( &entry->val, 0, sizeof(fd_snp_dest_meta_t) );
      entry->val.ip4_addr      = ip4_addr;
      entry->val.udp_port      = udp_port;
      entry->val.snp_available = snp_available;
      is_new = 1;
    }

    /* If two or more pubkeys show the same ip4_addr and udp_port in
       gossip (it has been observed in testnet), we need to avoid a
       ping-pong around has_changed.  The downside to this approach
       is that only the first entry in the gossip table will be
       processed here. */
    if( entry->val.update_idx == ctx->snp->dest_meta_update_idx ) continue;
    /* For every entry, whether new or not, the update index needs to
       be refreshed.  This is later used to detect (and delete)
       expired entries. */
    entry->val.update_idx = ctx->snp->dest_meta_update_idx;

    int has_changed = (!is_new) && (entry->val.snp_available != snp_available);

    if( FD_UNLIKELY( !!is_new || !!has_changed ) ) {
      entry->val.snp_available = snp_available;
      entry->val.snp_enabled   = 0;
      /* force a handshake if snp_available. */
      entry->val.snp_handshake_tstamp = 0;
    }
  }
  for( ulong i=0UL; i<ctx->enforced_cnt; i++ ) {
    fd_snp_dest_meta_map_t sentinel = { 0 };
    fd_snp_dest_meta_map_t * entry = fd_snp_dest_meta_map_query( ctx->snp->dest_meta_map, ctx->enforced[ i ], &sentinel );
    if( FD_LIKELY( !!entry->key ) ) {
      entry->val.snp_enabled = 1;
      entry->val.snp_enforced = 1;
    }
  }
}

static inline void
finalize_new_cluster_contact_info( fd_snp_tile_ctx_t * ctx ) {
  fd_stake_ci_dest_add_fini( ctx->stake_ci, ctx->new_dest_cnt );
}

static inline void
metrics_write( fd_snp_tile_ctx_t * ctx ) {
  /* All */
  FD_MCNT_SET  ( SNP, ALL_DEST_META_CNT,                      ctx->snp->metrics_all->dest_meta_cnt                     );
  FD_MCNT_SET  ( SNP, ALL_DEST_META_SNP_AVAILABLE_CNT,        ctx->snp->metrics_all->dest_meta_snp_available_cnt       );
  FD_MCNT_SET  ( SNP, ALL_DEST_META_SNP_ENABLED_CNT,          ctx->snp->metrics_all->dest_meta_snp_enabled_cnt         );
  FD_MCNT_SET  ( SNP, ALL_CONN_CUR_TOTAL,                     ctx->snp->metrics_all->conn_cur_total                    );
  FD_MCNT_SET  ( SNP, ALL_CONN_CUR_ESTABLISHED,               ctx->snp->metrics_all->conn_cur_established              );
  FD_MCNT_SET  ( SNP, ALL_CONN_ACC_TOTAL,                     ctx->snp->metrics_all->conn_acc_total                    );
  FD_MCNT_SET  ( SNP, ALL_CONN_ACC_ESTABLISHED,               ctx->snp->metrics_all->conn_acc_established              );
  FD_MCNT_SET  ( SNP, ALL_CONN_ACC_DROPPED,                   ctx->snp->metrics_all->conn_acc_dropped                  );
  FD_MCNT_SET  ( SNP, ALL_CONN_ACC_DROPPED_HANDSHAKE,         ctx->snp->metrics_all->conn_acc_dropped_handshake        );
  FD_MCNT_SET  ( SNP, ALL_CONN_ACC_DROPPED_ESTABLISHED,       ctx->snp->metrics_all->conn_acc_dropped_established      );
  FD_MCNT_SET  ( SNP, ALL_CONN_ACC_DROPPED_SET_IDENTITY,      ctx->snp->metrics_all->conn_acc_dropped_set_identity     );
  FD_MCNT_SET  ( SNP, ALL_TX_BYTES_VIA_UDP_TO_SNP_AVAIL_CNT,  ctx->snp->metrics_all->tx_bytes_via_udp_to_snp_avail_cnt );
  FD_MCNT_SET  ( SNP, ALL_TX_PKTS_VIA_UDP_TO_SNP_AVAIL_CNT,   ctx->snp->metrics_all->tx_pkts_via_udp_to_snp_avail_cnt  );
  FD_MCNT_SET  ( SNP, ALL_TX_BYTES_VIA_UDP_CNT,               ctx->snp->metrics_all->tx_bytes_via_udp_cnt              );
  FD_MCNT_SET  ( SNP, ALL_TX_BYTES_VIA_SNP_CNT,               ctx->snp->metrics_all->tx_bytes_via_snp_cnt              );
  FD_MCNT_SET  ( SNP, ALL_TX_PKTS_VIA_UDP_CNT,                ctx->snp->metrics_all->tx_pkts_via_udp_cnt               );
  FD_MCNT_SET  ( SNP, ALL_TX_PKTS_VIA_SNP_CNT,                ctx->snp->metrics_all->tx_pkts_via_snp_cnt               );
  FD_MCNT_SET  ( SNP, ALL_TX_PKTS_DROPPED_NO_CREDITS_CNT,     ctx->snp->metrics_all->tx_pkts_dropped_no_credits_cnt    );
  FD_MCNT_SET  ( SNP, ALL_RX_BYTES_CNT,                       ctx->snp->metrics_all->rx_bytes_cnt                      );
  FD_MCNT_SET  ( SNP, ALL_RX_BYTES_VIA_UDP_CNT,               ctx->snp->metrics_all->rx_bytes_via_udp_cnt              );
  FD_MCNT_SET  ( SNP, ALL_RX_BYTES_VIA_SNP_CNT,               ctx->snp->metrics_all->rx_bytes_via_snp_cnt              );
  FD_MCNT_SET  ( SNP, ALL_RX_PKTS_CNT,                        ctx->snp->metrics_all->rx_pkts_cnt                       );
  FD_MCNT_SET  ( SNP, ALL_RX_PKTS_VIA_UDP_CNT,                ctx->snp->metrics_all->rx_pkts_via_udp_cnt               );
  FD_MCNT_SET  ( SNP, ALL_RX_PKTS_VIA_SNP_CNT,                ctx->snp->metrics_all->rx_pkts_via_snp_cnt               );
  FD_MCNT_SET  ( SNP, ALL_RX_PKTS_DROPPED_NO_CREDITS_CNT,     ctx->snp->metrics_all->rx_pkts_dropped_no_credits_cnt    );

  /* Enforced */
  FD_MCNT_SET  ( SNP, ENF_DEST_META_CNT,                      ctx->snp->metrics_enf->dest_meta_cnt                     );
  FD_MCNT_SET  ( SNP, ENF_DEST_META_SNP_AVAILABLE_CNT,        ctx->snp->metrics_enf->dest_meta_snp_available_cnt       );
  FD_MCNT_SET  ( SNP, ENF_DEST_META_SNP_ENABLED_CNT,          ctx->snp->metrics_enf->dest_meta_snp_enabled_cnt         );
  FD_MCNT_SET  ( SNP, ENF_CONN_CUR_TOTAL,                     ctx->snp->metrics_enf->conn_cur_total                    );
  FD_MCNT_SET  ( SNP, ENF_CONN_CUR_ESTABLISHED,               ctx->snp->metrics_enf->conn_cur_established              );
  FD_MCNT_SET  ( SNP, ENF_CONN_ACC_TOTAL,                     ctx->snp->metrics_enf->conn_acc_total                    );
  FD_MCNT_SET  ( SNP, ENF_CONN_ACC_ESTABLISHED,               ctx->snp->metrics_enf->conn_acc_established              );
  FD_MCNT_SET  ( SNP, ENF_CONN_ACC_DROPPED,                   ctx->snp->metrics_enf->conn_acc_dropped                  );
  FD_MCNT_SET  ( SNP, ENF_CONN_ACC_DROPPED_HANDSHAKE,         ctx->snp->metrics_enf->conn_acc_dropped_handshake        );
  FD_MCNT_SET  ( SNP, ENF_CONN_ACC_DROPPED_ESTABLISHED,       ctx->snp->metrics_enf->conn_acc_dropped_established      );
  FD_MCNT_SET  ( SNP, ENF_CONN_ACC_DROPPED_SET_IDENTITY,      ctx->snp->metrics_enf->conn_acc_dropped_set_identity     );
  FD_MCNT_SET  ( SNP, ENF_TX_BYTES_VIA_UDP_TO_SNP_AVAIL_CNT,  ctx->snp->metrics_enf->tx_bytes_via_udp_to_snp_avail_cnt );
  FD_MCNT_SET  ( SNP, ENF_TX_PKTS_VIA_UDP_TO_SNP_AVAIL_CNT,   ctx->snp->metrics_enf->tx_pkts_via_udp_to_snp_avail_cnt  );
  FD_MCNT_SET  ( SNP, ENF_TX_BYTES_VIA_UDP_CNT,               ctx->snp->metrics_enf->tx_bytes_via_udp_cnt              );
  FD_MCNT_SET  ( SNP, ENF_TX_BYTES_VIA_SNP_CNT,               ctx->snp->metrics_enf->tx_bytes_via_snp_cnt              );
  FD_MCNT_SET  ( SNP, ENF_TX_PKTS_VIA_UDP_CNT,                ctx->snp->metrics_enf->tx_pkts_via_udp_cnt               );
  FD_MCNT_SET  ( SNP, ENF_TX_PKTS_VIA_SNP_CNT,                ctx->snp->metrics_enf->tx_pkts_via_snp_cnt               );
  FD_MCNT_SET  ( SNP, ENF_TX_PKTS_DROPPED_NO_CREDITS_CNT,     ctx->snp->metrics_enf->tx_pkts_dropped_no_credits_cnt    );
  FD_MCNT_SET  ( SNP, ENF_RX_BYTES_CNT,                       ctx->snp->metrics_enf->rx_bytes_cnt                      );
  FD_MCNT_SET  ( SNP, ENF_RX_BYTES_VIA_UDP_CNT,               ctx->snp->metrics_enf->rx_bytes_via_udp_cnt              );
  FD_MCNT_SET  ( SNP, ENF_RX_BYTES_VIA_SNP_CNT,               ctx->snp->metrics_enf->rx_bytes_via_snp_cnt              );
  FD_MCNT_SET  ( SNP, ENF_RX_PKTS_CNT,                        ctx->snp->metrics_enf->rx_pkts_cnt                       );
  FD_MCNT_SET  ( SNP, ENF_RX_PKTS_VIA_UDP_CNT,                ctx->snp->metrics_enf->rx_pkts_via_udp_cnt               );
  FD_MCNT_SET  ( SNP, ENF_RX_PKTS_VIA_SNP_CNT,                ctx->snp->metrics_enf->rx_pkts_via_snp_cnt               );
  FD_MCNT_SET  ( SNP, ENF_RX_PKTS_DROPPED_NO_CREDITS_CNT,     ctx->snp->metrics_enf->rx_pkts_dropped_no_credits_cnt    );
}

static inline int
before_frag( fd_snp_tile_ctx_t * ctx,
             ulong               in_idx,
             ulong               seq FD_PARAM_UNUSED,
             ulong               sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED ) )    return 0;
  else if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_NET_SHRED ) ) return fd_disco_netmux_sig_proto( sig )!=DST_PROTO_SHRED;

  return 0;
}

static void
during_frag( fd_snp_tile_ctx_t * ctx,
             ulong               in_idx,
             ulong               seq FD_PARAM_UNUSED,
             ulong               sig FD_PARAM_UNUSED,
             ulong               chunk,
             ulong               sz,
             ulong               ctl ) {

  ctx->skip_frag = 0;

  ctx->tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  switch( ctx->in_kind[ in_idx ] ) {

    case IN_KIND_SHRED: {
      /* Applications are unreliable channels, we copy the incoming packet
         and we'll process it in after_frag. */
      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
              ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      ctx->packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
      fd_ip4_udp_hdrs_t * hdr  = (fd_ip4_udp_hdrs_t *)dcache_entry;
      uint ip4_daddr     = hdr->ip4->daddr;
      ushort udp_dport   = fd_ushort_bswap( hdr->udp->net_dport );

      int snp_enabled = 0;
      ulong dest_meta_map_key = fd_snp_dest_meta_map_key_from_parts( ip4_daddr, udp_dport );
      fd_snp_dest_meta_map_t sentinel = { 0 };
      fd_snp_dest_meta_map_t * entry = fd_snp_dest_meta_map_query( ctx->snp->dest_meta_map, dest_meta_map_key, &sentinel );
      if( !!entry->key ) {
        snp_enabled = entry->val.snp_enabled;
      }

      fd_snp_meta_t meta = fd_snp_meta_from_parts( snp_enabled ? FD_SNP_META_PROTO_V1 : FD_SNP_META_PROTO_UDP, 0/*app_id*/, ip4_daddr, udp_dport );
      int res = fd_snp_app_send( ctx->snp_app, ctx->packet, FD_NET_MTU, dcache_entry + sizeof(fd_ip4_udp_hdrs_t), sz - sizeof(fd_ip4_udp_hdrs_t), meta );
      if( res < 0 ) {
        ctx->skip_frag = 1;
      }
      ctx->packet_sz = (ulong)res;
      ctx->meta = meta;
    } break;

    case IN_KIND_NET_SHRED: {
      /* Net is an unreliable channel, we copy the incoming packet
         and we'll process it in after_frag. */
      uchar const * dcache_entry = fd_net_rx_translate_frag( &ctx->in[ in_idx ].net_rx, chunk, ctl, sz );
      ulong hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
      FD_TEST( hdr_sz <= sz ); /* Should be ensured by the net tile */

      /* on the shred channel we receive both packets from shred and repair */
      if( sz > 45
          && *(dcache_entry + 42UL)=='S'
          && *(dcache_entry + 43UL)=='N'
          && *(dcache_entry + 44UL)=='P'
          && ( *(dcache_entry + 45UL) & 0x0F ) != FD_SNP_TYPE_PAYLOAD ) {
          ctx->packet = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
      } else {
        ctx->packet = fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
      }

      memcpy( ctx->packet, dcache_entry, sz );
      ctx->packet_sz = sz;
      ctx->sig = sig;
    } break;

    case IN_KIND_GOSSIP:
      /* Gossip is a reliable channel, we can process new contacts here */
      break;

    case IN_KIND_SIGN: {
      /* Sign is an unreliable channel but guaranteed not to overflow.
         Therefore, we can process new signatures here. */
      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz!=FD_ED25519_SIG_SZ ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
              ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_memcpy( ctx->signature, dcache_entry, FD_ED25519_SIG_SZ );
    } break;

    case IN_KIND_CRDS: {
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                    ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      handle_new_cluster_contact_info( ctx, dcache_entry );
    } break;

    case IN_KIND_STAKE: {
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
        FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
                    ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      fd_stake_ci_stake_msg_init( ctx->stake_ci, fd_type_pun_const( dcache_entry ) );
    } break;
  }
}

static void
after_frag( fd_snp_tile_ctx_t * ctx,
            ulong               in_idx,
            ulong               seq     FD_PARAM_UNUSED,
            ulong               sig,
            ulong               sz      FD_PARAM_UNUSED,
            ulong               tsorig  FD_PARAM_UNUSED,
            ulong               _tspub  FD_PARAM_UNUSED,
            fd_stem_context_t * stem  ) {
  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  /* make sure to set ctx->stem before invoking any snp callback. */
  ctx->stem = stem;

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_SHRED: {
      /* Process all applications (with multicast) */
      fd_snp_send( ctx->snp, ctx->packet, ctx->packet_sz, ctx->meta );
    } break;

    case IN_KIND_NET_SHRED: {
      /* Process incoming network packets */
      fd_snp_process_packet( ctx->snp, ctx->packet, ctx->packet_sz );
    } break;

    case IN_KIND_GOSSIP:
      /* Gossip */
      break;

    case IN_KIND_SIGN: {
      /* Sign */
      fd_snp_process_signature( ctx->snp, sig /*session_id*/, ctx->signature );
    } break;

    case IN_KIND_CRDS: {
      finalize_new_cluster_contact_info( ctx );
    } break;

    case IN_KIND_STAKE: {
      fd_stake_ci_stake_msg_fini( ctx->stake_ci );
    } break;
  }
}

static int
snp_callback_tx( void const *  _ctx,
                 uchar const * packet,
                 ulong         packet_sz,
                 fd_snp_meta_t meta ) {

  fd_snp_tile_ctx_t * ctx = (fd_snp_tile_ctx_t *)_ctx;
  uint dst_ip_meta;
  ushort dst_port;
  ulong proto;
  fd_snp_meta_into_parts( &proto, NULL, &dst_ip_meta, &dst_port, meta );

  uint dst_ip = fd_uint_load_4( packet+FD_SNP_IP_DST_ADDR_OFF );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = fd_disco_netmux_sig( dst_ip, 0U, dst_ip, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );

  /* memcpy is done in during_frag, it's only needed for buffered packets */
  if( FD_UNLIKELY( meta & FD_SNP_META_OPT_BUFFERED ) ) {
    memcpy( fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk ), packet, packet_sz );
  }
  fd_stem_publish( ctx->stem, NET_OUT_IDX /*ctx->net_out_idx*/, sig, ctx->net_out_chunk, packet_sz, 0UL, ctx->tsorig, tspub );
  ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, packet_sz, ctx->net_out_chunk0, ctx->net_out_wmark );

  return FD_SNP_SUCCESS;
}

static int
snp_callback_rx( void const *  _ctx,
                 uchar const * packet,
                 ulong         packet_sz,
                 fd_snp_meta_t meta ) {
  fd_snp_tile_ctx_t * ctx = (fd_snp_tile_ctx_t *)_ctx;
  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = ctx->sig;
  FD_TEST( ctx->stem != NULL );
  /* No memcpy needed here - already done in during_frag. */

  if( FD_UNLIKELY( meta & FD_SNP_META_OPT_BUFFERED ) ) {
    /* This calculation of sig is very specific to the shred tile. */
    fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)(packet + sizeof(fd_eth_hdr_t));
    ulong hdr_sz = sizeof(fd_eth_hdr_t) + FD_IP4_GET_LEN( *ip4_hdr ) + sizeof(fd_udp_hdr_t);
    sig = fd_disco_netmux_sig( 0/*unsued*/, 0/*unsued*/, 0/*unsued*/, DST_PROTO_SHRED, hdr_sz );
    /* copy the buffered packet */
    memcpy( ctx->packet, packet, packet_sz );
  }

  ulong adj_ctl       = 0UL;
  ulong adj_packet_sz = packet_sz;
  ulong proto;
  fd_snp_meta_into_parts( &proto, NULL, NULL, NULL, meta );
  if( FD_LIKELY( proto != FD_SNP_META_PROTO_UDP ) ) {
    adj_packet_sz -= ( 12 /*SNP*/ + 3/*TL*/ + 19 /*MAC*/ );
    fd_ip4_hdr_t * ip4_hdr = (fd_ip4_hdr_t *)(packet + sizeof(fd_eth_hdr_t));
    ulong hdr_sz = sizeof(fd_eth_hdr_t) + FD_IP4_GET_LEN( *ip4_hdr ) + sizeof(fd_udp_hdr_t);
    memmove( ctx->packet+hdr_sz, packet+hdr_sz+( 12 /*SNP*/ + 3/*TL*/ ), adj_packet_sz-hdr_sz );
  }

  fd_stem_publish( ctx->stem, SHRED_OUT_IDX /*ctx->shred_out_idx*/, sig, ctx->shred_out_chunk, adj_packet_sz, adj_ctl, ctx->tsorig, tspub );
  ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, packet_sz, ctx->shred_out_chunk0, ctx->shred_out_wmark );
  return FD_SNP_SUCCESS;
}

static int
snp_callback_sign( void const *  _ctx,
                   ulong         session_id,
                   uchar const   to_sign[ FD_SNP_TO_SIGN_SZ ] ) {
  (void)to_sign;
  fd_snp_tile_ctx_t * ctx = (fd_snp_tile_ctx_t *)_ctx;

  ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong sig = (ulong)FD_KEYGUARD_SIGN_TYPE_ULONG_ID_ED25519;
  FD_TEST( ctx->stem != NULL );

  uchar * dst = fd_chunk_to_laddr( ctx->sign_out_mem, ctx->sign_out_chunk );
  memcpy( dst+0UL, &session_id, sizeof(ulong) );
  memcpy( dst+sizeof(ulong), to_sign, FD_SNP_TO_SIGN_SZ - sizeof(ulong) );
  fd_stem_publish( ctx->stem, SIGN_OUT_IDX /*ctx->sign_out_idx*/, sig, ctx->sign_out_chunk, FD_SNP_TO_SIGN_SZ, 0UL, ctx->tsorig, tspub );
  ctx->sign_out_chunk = fd_dcache_compact_next( ctx->sign_out_chunk, FD_SNP_TO_SIGN_SZ, ctx->sign_out_chunk0, ctx->sign_out_wmark );
  return FD_SNP_SUCCESS;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snp_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_snp_tile_ctx_t ), sizeof( fd_snp_tile_ctx_t ) );

  if( FD_UNLIKELY( !strcmp( tile->snp.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->snp.identity_key_path, /* pubkey only: */ 1 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_LIKELY( tile->out_cnt==3UL ) ) { /* frankendancer */
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[NET_OUT_IDX]].name,    "snp_net"    ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SHRED_OUT_IDX]].name,  "snp_shred"  ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SIGN_OUT_IDX]].name,   "snp_sign"   ) );
  } else if( FD_LIKELY( tile->out_cnt==4UL ) ) { /* firedancer */
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[NET_OUT_IDX]].name,    "snp_net"    ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SHRED_OUT_IDX]].name,  "snp_shred"  ) );
    FD_TEST( 0==strcmp( topo->links[tile->out_link_id[SIGN_OUT_IDX]].name,   "snp_sign"   ) );
  } else {
    FD_LOG_ERR(( "snp tile has unexpected cnt of output links %lu", tile->out_cnt ));
  }

  if( FD_UNLIKELY( !tile->out_cnt ) )
    FD_LOG_ERR(( "snp tile has no primary output link" ));

  ulong snp_store_mcache_depth = tile->snp.depth;
  if( topo->links[ tile->out_link_id[ 0 ] ].depth != snp_store_mcache_depth )
    FD_LOG_ERR(( "snp tile out depths are not equal %lu %lu",
                 topo->links[ tile->out_link_id[ 0 ] ].depth, snp_store_mcache_depth ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snp_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_snp_tile_ctx_t ), sizeof( fd_snp_tile_ctx_t ) );

  /* Round robin */
  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;

  /* SNP */
  fd_snp_limits_t limits = snp_limits( tile );
  fd_snp_app_limits_t limits_app = { 0 };

  void * _stake_ci = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_ci_align(),     fd_stake_ci_footprint()     );
  void * _snp      = FD_SCRATCH_ALLOC_APPEND( l, fd_snp_align(),          fd_snp_footprint( &limits ) );
  void * _snp_app  = FD_SCRATCH_ALLOC_APPEND( l, fd_snp_app_align(),      fd_snp_app_footprint( &limits_app )  );

  ctx->stake_ci = fd_stake_ci_join( fd_stake_ci_new( _stake_ci, ctx->identity_key ) );

  fd_snp_t * snp = fd_snp_join( fd_snp_new( _snp, &limits ) );
  ctx->snp = snp;
  snp->cb.ctx = ctx;
  snp->cb.rx = snp_callback_rx;
  snp->cb.tx = snp_callback_tx;
  snp->cb.sign = snp_callback_sign;
  snp->apps_cnt = 1;
  snp->apps[0].port = 8003;
  snp->apps[0].multicast_ip = (uint)((239 << 24) + (0 << 16) + (192 << 8) + 18);
  /* Flow control initialization.  The allocation per connection is
     arbitrary at the moment. */
  snp->flow_cred_alloc = (long)( 4 * 1024 * 1024 ); /* 4MiB */

  FD_TEST( fd_snp_init( snp ) );
  fd_memcpy( snp->config.identity, ctx->identity_key, sizeof(fd_pubkey_t) );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  /* Channels */
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY(      !strcmp( link->name, "net_shred"   ) ) ) {
      ctx->in_kind[ i ] = IN_KIND_NET_SHRED;
      fd_net_rx_bounds_init( &ctx->in[ i ].net_rx, link->dcache );
      continue; /* only net_rx needs to be set in this case. */
    }

    if( FD_LIKELY(      !strcmp( link->name, "shred_snp"   ) ) ) ctx->in_kind[ i ] = IN_KIND_SHRED;
    else if( FD_LIKELY( !strcmp( link->name, "crds_shred"  ) ) ) ctx->in_kind[ i ] = IN_KIND_CRDS;  /* reusing crds_shred */
    else if( FD_LIKELY( !strcmp( link->name, "stake_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_STAKE;
    else if( FD_LIKELY( !strcmp( link->name, "sign_snp"    ) ) ) ctx->in_kind[ i ] = IN_KIND_SIGN;
    else FD_LOG_ERR(( "shred tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( !!link->mtu ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    }
  }

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ NET_OUT_IDX ] ];

  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_topo_link_t * shred_out = &topo->links[ tile->out_link_id[ SHRED_OUT_IDX ] ];

  ctx->shred_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( shred_out->dcache ), shred_out->dcache );
  ctx->shred_out_mem    = topo->workspaces[ topo->objs[ shred_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->shred_out_wmark  = fd_dcache_compact_wmark ( ctx->shred_out_mem, shred_out->dcache, shred_out->mtu );
  ctx->shred_out_chunk  = ctx->shred_out_chunk0;

  fd_topo_link_t * sign_out = &topo->links[ tile->out_link_id[ SIGN_OUT_IDX ] ];

  ctx->sign_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( sign_out->dcache ), sign_out->dcache );
  ctx->sign_out_mem    = topo->workspaces[ topo->objs[ sign_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->sign_out_wmark  = fd_dcache_compact_wmark ( ctx->sign_out_mem, sign_out->dcache, sign_out->mtu );
  ctx->sign_out_chunk  = ctx->sign_out_chunk0;

  ctx->shred_cnt = 0UL;

  ctx->packet = NULL;

  ctx->enforced_cnt = tile->snp.enforced_destinations_cnt;
  for( ulong i=0UL; i<tile->snp.enforced_destinations_cnt; i++ ) {
    uint   ip4_addr = tile->snp.enforced_destinations[ i ].ip;
    ushort udp_port = tile->snp.enforced_destinations[ i ].port;
    ctx->enforced[ i ] = fd_snp_dest_meta_map_key_from_parts( ip4_addr, udp_port );
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  ctx->stem = NULL; /* to be set before every snp callback function */

  fd_snp_app_t * snp_app = fd_snp_app_join( fd_snp_app_new( _snp_app, &limits_app ) );
  ctx->snp_app = snp_app;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;
  populate_sock_filter_policy_fd_snp_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snp_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (2UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snp_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snp_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snp = {
  .name                     = "snp",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
