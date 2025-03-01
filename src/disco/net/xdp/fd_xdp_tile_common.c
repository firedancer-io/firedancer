/* Runtime parts of the net tile.  Pretty much all of the functions
   below are inlined into a single big run loop. */

#include "fd_xdp_tile_private.h"
#include "../../metrics/fd_metrics.h"
#include "../../../util/log/fd_dtrace.h"

#include <errno.h>
#include <sys/socket.h> /* getsockopt */

/* fd_net_flusher_inc marks a new packet as enqueued. */

static inline void
fd_net_flusher_inc( fd_net_flusher_t * flusher,
                    long               now ) {
  flusher->pending_cnt++;
  long next_flush = now + flusher->tail_flush_backoff;
  flusher->next_tail_flush_ticks = fd_long_min( flusher->next_tail_flush_ticks, next_flush );
}

/* fd_net_flusher_check returns 1 if a sendto() wakeup should be issued
   immediately.  now is a recent fd_tickcount() value.
   If tx_ring_empty==0 then the kernel is caught up with the net tile
   on the XDP TX ring.  (Otherwise, the kernel is behind the net tile) */

static inline int
fd_net_flusher_check( fd_net_flusher_t * flusher,
                      long               now,
                      int                tx_ring_empty ) {
  int flush_level   = flusher->pending_cnt >= flusher->pending_wmark;
  int flush_timeout = now >= flusher->next_tail_flush_ticks;
  int flush         = flush_level || flush_timeout;
  if( !flush ) return 0;
  if( FD_UNLIKELY( tx_ring_empty ) ) {
    /* Flush requested but caught up */
    flusher->pending_cnt           = 0UL;
    flusher->next_tail_flush_ticks = LONG_MAX;
    return 0;
  }
  return 1;
}

/* fd_net_flusher_wakeup signals a sendto() wakeup was done.  now is a
   recent fd_tickcount() value.
   FIXME randomize wakeup */

static inline void
fd_net_flusher_wakeup( fd_net_flusher_t * flusher,
                       long               now ) {
  flusher->pending_cnt           = 0UL;
  flusher->next_tail_flush_ticks = now + flusher->tail_flush_backoff;
}

/* metrics_write copies thread-local metrics to the metrics shm region. */

static void
metrics_write( fd_net_ctx_t * ctx ) {
  FD_MCNT_SET(   NET, RX_PKT_CNT,          ctx->metrics.rx_pkt_cnt          );
  FD_MCNT_SET(   NET, RX_BYTES_TOTAL,      ctx->metrics.rx_bytes_total      );
  FD_MCNT_SET(   NET, RX_UNDERSZ_CNT,      ctx->metrics.rx_undersz_cnt      );
  FD_MCNT_SET(   NET, RX_FILL_BLOCKED_CNT, ctx->metrics.rx_fill_blocked_cnt );
  FD_MCNT_SET(   NET, RX_BACKPRESSURE_CNT, ctx->metrics.rx_backp_cnt        );
  FD_MGAUGE_SET( NET, RX_BUSY_CNT, (ulong)fd_long_max( ctx->metrics.rx_busy_cnt, 0L ) );
  FD_MGAUGE_SET( NET, RX_IDLE_CNT, (ulong)fd_long_max( ctx->metrics.rx_idle_cnt, 0L ) );
  FD_MGAUGE_SET( NET, TX_BUSY_CNT, (ulong)fd_long_max( ctx->metrics.tx_busy_cnt, 0L ) );
  FD_MGAUGE_SET( NET, TX_IDLE_CNT, (ulong)fd_long_max( ctx->metrics.tx_idle_cnt, 0L ) );

  FD_MCNT_SET( NET, TX_SUBMIT_CNT,        ctx->metrics.tx_submit_cnt     );
  FD_MCNT_SET( NET, TX_COMPLETE_CNT,      ctx->metrics.tx_complete_cnt   );
  FD_MCNT_SET( NET, TX_BYTES_TOTAL,       ctx->metrics.tx_bytes_total    );
  FD_MCNT_SET( NET, TX_ROUTE_FAIL_CNT,    ctx->metrics.tx_route_fail_cnt );
  FD_MCNT_SET( NET, TX_NEIGHBOR_FAIL_CNT, ctx->metrics.tx_neigh_fail_cnt );
  FD_MCNT_SET( NET, TX_FULL_FAIL_CNT,     ctx->metrics.tx_full_fail_cnt  );

  FD_MCNT_SET( NET, XSK_TX_WAKEUP_CNT,    ctx->metrics.xsk_tx_wakeup_cnt    );
  FD_MCNT_SET( NET, XSK_RX_WAKEUP_CNT,    ctx->metrics.xsk_rx_wakeup_cnt    );
}

/* poll_xdp_statistics copies kernel XDP counters to the metrics shm
   region. */

static void
poll_xdp_statistics( fd_net_ctx_t * ctx ) {
  struct xdp_statistics_v1 stats = {0};
  ulong xsk_cnt = ctx->xsk_cnt;
  for( ulong j=0UL; j<xsk_cnt; j++ ) {
    struct xdp_statistics_v1 sub_stats;
    uint optlen = (uint)sizeof(struct xdp_statistics_v1);
    if( FD_UNLIKELY( -1==getsockopt( ctx->xsk[ j ].xsk_fd, SOL_XDP, XDP_STATISTICS, &sub_stats, &optlen ) ) )
      FD_LOG_ERR(( "getsockopt(SOL_XDP, XDP_STATISTICS) failed: %s", strerror( errno ) ));
    if( FD_UNLIKELY( optlen!=sizeof(struct xdp_statistics_v0) &&
                     optlen!=sizeof(struct xdp_statistics_v1) ) ) {
      FD_LOG_ERR(( "getsockopt(SOL_XDP, XDP_STATISTICS) returned unexpected size %u", optlen ));
    }
    stats.rx_dropped               += sub_stats.rx_dropped;
    stats.rx_invalid_descs         += sub_stats.rx_invalid_descs;
    stats.tx_invalid_descs         += sub_stats.tx_invalid_descs;
    stats.rx_ring_full             += sub_stats.rx_ring_full;
    stats.rx_fill_ring_empty_descs += sub_stats.rx_fill_ring_empty_descs;
    stats.tx_ring_empty_descs      += sub_stats.tx_ring_empty_descs;
  }

  FD_MCNT_SET( NET, XDP_RX_DROPPED_OTHER,         stats.rx_dropped               );
  FD_MCNT_SET( NET, XDP_RX_INVALID_DESCS,         stats.rx_invalid_descs         );
  FD_MCNT_SET( NET, XDP_TX_INVALID_DESCS,         stats.tx_invalid_descs         );
  FD_MCNT_SET( NET, XDP_RX_RING_FULL,             stats.rx_ring_full             );
  FD_MCNT_SET( NET, XDP_RX_FILL_RING_EMPTY_DESCS, stats.rx_fill_ring_empty_descs );
  FD_MCNT_SET( NET, XDP_TX_RING_EMPTY_DESCS,      stats.tx_ring_empty_descs      );
}

/* net_is_fatal_xdp_error returns 1 if the given errno returned by an
   XDP API indicates a non-recoverable error code.  The net tile should
   crash if it sees such an error so the problem does not go undetected.
   Otherwise, returns 0. */

static int
net_is_fatal_xdp_error( int err ) {
  return err==ESOCKTNOSUPPORT || err==EOPNOTSUPP || err==EINVAL ||
         err==EPERM;
}

/* net_tx_ready returns 1 if the current XSK is ready to submit a TX send
   job.  If the XSK is blocked for sends, returns 0.  Reasons for block
   include:
   - No XSK TX buffer is available
   - XSK TX ring is full */

static int
net_tx_ready( fd_net_ctx_t * ctx,
              uint           if_idx ) {
  fd_xsk_t *           xsk     = &ctx->xsk[ if_idx ];
  fd_xdp_ring_t *      tx_ring = &xsk->ring_tx;
  fd_net_free_ring_t * free    = &ctx->free_tx;
  if( free->prod == free->cons ) return 0; /* drop */
  if( tx_ring->prod - tx_ring->cons >= tx_ring->depth ) return 0; /* drop */
  return 1;
}

/* net_seq_refresh updates cached sequence numbers. */

static void
net_seq_refresh( fd_xsk_t * xsk ) {
  xsk->ring_fr.cached_cons = FD_VOLATILE_CONST( *xsk->ring_fr.cons );
  xsk->ring_rx.cached_prod = FD_VOLATILE_CONST( *xsk->ring_rx.prod );
  xsk->ring_tx.cached_cons = FD_VOLATILE_CONST( *xsk->ring_tx.cons );
  xsk->ring_cr.cached_prod = FD_VOLATILE_CONST( *xsk->ring_cr.prod );
}

/* net_rx_wakeup triggers xsk_recvmsg to run in the kernel.  Needs to be
   called periodically in order to receive packets. */

static void
net_rx_wakeup( fd_net_ctx_t * ctx,
               fd_xsk_t *     xsk ) {
  struct msghdr _ignored[ 1 ] = { 0 };
  if( FD_UNLIKELY( -1==recvmsg( xsk->xsk_fd, _ignored, MSG_DONTWAIT ) ) ) {
    if( FD_UNLIKELY( net_is_fatal_xdp_error( errno ) ) ) {
      FD_LOG_ERR(( "xsk recvmsg failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( errno!=EAGAIN ) ) {
      long ts = fd_log_wallclock();
      if( ts > ctx->log_suppress_until_ns ) {
        FD_LOG_WARNING(( "xsk recvmsg failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
        ctx->log_suppress_until_ns = ts + (long)1e9;
      }
    }
  }
  net_seq_refresh( xsk );
  ctx->metrics.xsk_rx_wakeup_cnt++;
}

/* net_tx_wakeup triggers xsk_sendmsg to run in the kernel.  Needs to be
   called periodically in order to transmit packets. */

static void
net_tx_wakeup( fd_net_ctx_t * ctx,
               fd_xsk_t *     xsk,
               int *          charge_busy ) {
  if( xsk->ring_tx.cached_prod == xsk->ring_tx.cached_cons ) return;
  *charge_busy = 1;
  if( FD_UNLIKELY( -1==sendto( xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0 ) ) ) {
    if( FD_UNLIKELY( net_is_fatal_xdp_error( errno ) ) ) {
      FD_LOG_ERR(( "xsk sendto failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( errno!=EAGAIN ) ) {
      long ts = fd_log_wallclock();
      if( ts > ctx->log_suppress_until_ns ) {
        FD_LOG_WARNING(( "xsk sendto failed xsk_fd=%d (%i-%s)", xsk->xsk_fd, errno, fd_io_strerror( errno ) ));
        ctx->log_suppress_until_ns = ts + (long)1e9;
      }
    }
  }
  net_seq_refresh( xsk );
  ctx->metrics.xsk_tx_wakeup_cnt++;
}

static void
metrics_collect( fd_net_ctx_t * ctx ) {
  long now = fd_tickcount();

  ctx->metrics.rx_busy_cnt = 0UL;
  ctx->metrics.rx_idle_cnt = 0UL;
  ctx->metrics.tx_busy_cnt = 0UL;
  ctx->metrics.tx_idle_cnt = fd_seq_diff( ctx->free_tx.prod, ctx->free_tx.cons );
  for( uint j=0U; j<ctx->xsk_cnt; j++ ) {
    fd_xsk_t * xsk = &ctx->xsk[ j ];
    ctx->metrics.rx_busy_cnt += (long)(int)( xsk->ring_rx.cached_prod - xsk->ring_rx.cached_cons );
    ctx->metrics.rx_idle_cnt += (long)(int)( xsk->ring_fr.cached_prod - xsk->ring_fr.cached_cons );
    ctx->metrics.tx_busy_cnt += (long)(int)( xsk->ring_tx.cached_prod - xsk->ring_tx.cached_cons );
    ctx->metrics.tx_busy_cnt += (long)(int)( xsk->ring_cr.cached_prod - xsk->ring_cr.cached_cons );
  }

  if( now > ctx->next_xdp_stats_refresh ) {
    ctx->next_xdp_stats_refresh = now + ctx->xdp_stats_interval_ticks;
    poll_xdp_statistics( ctx );
  }
}

/* net_tx_route resolves the destination interface index, src MAC address,
   and dst MAC address.  Returns 1 on success, 0 on failure.  On success,
   tx_op->{if_idx,mac_addrs} is set. */

static int
net_tx_route( fd_net_ctx_t * ctx,
              uint           dst_ip ) {

  /* Route lookup */

  fd_fib4_hop_t hop[2] = {0};
  fd_fib4_lookup( ctx->fib_local, hop+0, dst_ip, 0UL );
  fd_fib4_lookup( ctx->fib_main,  hop+1, dst_ip, 0UL );
  fd_fib4_hop_t const * next_hop = fd_fib4_hop_or( hop+0, hop+1 );

  uint rtype  = next_hop->rtype;
  uint if_idx = next_hop->if_idx;

  if( FD_UNLIKELY( rtype==FD_FIB4_RTYPE_LOCAL ) ) {
    rtype  = FD_FIB4_RTYPE_UNICAST;
    if_idx = 1;
  }

  if( FD_UNLIKELY( rtype!=FD_FIB4_RTYPE_UNICAST ) ) {
    ctx->metrics.tx_route_fail_cnt++;
    return 0;
  }

  if( if_idx==1 ) {
    /* Set Ethernet src and dst address to 00:00:00:00:00:00 */
    memset( ctx->tx_op.mac_addrs, 0, 12UL );
    ctx->tx_op.if_idx = 1;
    return 1;
  }

  if( FD_UNLIKELY( if_idx!=ctx->xsk[ 0 ].if_idx ) ) {
    ctx->metrics.tx_no_xdp_cnt++;
    return 0;
  }
  ctx->tx_op.if_idx = 0;

  /* Neighbor resolve */

  uint neigh_ip = next_hop->ip4_gw;
  if( !neigh_ip ) neigh_ip = dst_ip;

  fd_neigh4_hmap_query_t neigh_query[1];
  int neigh_res = fd_neigh4_hmap_query_try( ctx->neigh4, &neigh_ip, NULL, neigh_query, 0 );
  if( FD_UNLIKELY( neigh_res!=FD_MAP_SUCCESS ) ) {
    /* Neighbor not found */
    fd_netlink_neigh4_solicit( ctx->neigh4_solicit, neigh_ip, if_idx, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }
  fd_neigh4_entry_t const * neigh = fd_neigh4_hmap_query_ele_const( neigh_query );
  if( FD_UNLIKELY( neigh->state != FD_NEIGH4_STATE_ACTIVE ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }

  memcpy( ctx->tx_op.mac_addrs+0, neigh->mac_addr,   6 );
  memcpy( ctx->tx_op.mac_addrs+6, ctx->src_mac_addr, 6 );

  if( FD_UNLIKELY( fd_neigh4_hmap_query_test( neigh_query ) ) ) {
    ctx->metrics.tx_neigh_fail_cnt++;
    return 0;
  }

  return 1;
}

/* before_frag is called when a new metadata descriptor for a TX job is
   found.  This callback determines whether this net tile is responsible
   for the TX job.  If so, it prepares the TX op for the during_frag and
   after_frag callbacks. */

static inline int
before_frag( fd_net_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig ) {
  (void)in_idx; (void)seq;

  /* Find interface index of next packet */

  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_OUTGOING ) ) return 1;

  uint dst_ip = fd_disco_netmux_sig_dst_ip( sig );
  if( FD_UNLIKELY( !net_tx_route( ctx, dst_ip ) ) ) return 1;

  uint net_tile_id  = ctx->net_tile_id;
  uint net_tile_cnt = ctx->net_tile_cnt;
  uint if_idx       = ctx->tx_op.if_idx;
  if( FD_UNLIKELY( if_idx>=ctx->xsk_cnt ) ) return 1; /* ignore */

  /* Load balance TX */

  uint hash       = (uint)fd_disco_netmux_sig_hash( sig );
  uint target_idx = hash % net_tile_cnt;
  if( if_idx==1 ) target_idx = 0; /* loopback always targets tile 0 */

  /* Skip if another net tile is responsible for this packet */

  if( net_tile_id!=target_idx ) return 1; /* ignore */

  /* Skip if TX is blocked */

  if( FD_UNLIKELY( !net_tx_ready( ctx, if_idx ) ) ) {
    ctx->metrics.tx_full_fail_cnt++;
    return 1;
  }

  /* Allocate buffer for receive */

  fd_net_free_ring_t * free      = &ctx->free_tx;
  ulong                alloc_seq = free->cons;
  void *               frame     = (void *)free->queue[ alloc_seq % free->depth ];
  free->cons = fd_seq_inc( alloc_seq, 1UL );

  ctx->tx_op.if_idx    = if_idx;
  ctx->tx_op.frame     = frame;

  return 0; /* continue */
}

/* during_frag is called when before_frag has committed to transmit an
   outgoing packet. */

static inline void
during_frag( fd_net_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq FD_PARAM_UNUSED,
             ulong          sig FD_PARAM_UNUSED,
             ulong          chunk,
             ulong          sz,
             ulong          ctl FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  if( FD_UNLIKELY( sz<14UL ) )
    FD_LOG_ERR(( "packet too small %lu (in_idx=%lu)", sz, in_idx ));

  void * frame = ctx->tx_op.frame;
  if( FD_UNLIKELY( (ulong)frame < (ulong)ctx->umem_frame0 ) )
    FD_LOG_ERR(( "frame %p out of bounds (below %p)", frame, (void *)ctx->umem_frame0 ));
  ulong umem_off = (ulong)frame - (ulong)ctx->umem_frame0;
  if( FD_UNLIKELY( (ulong)umem_off > (ulong)ctx->umem_sz ) )
    FD_LOG_ERR(( "frame %p out of bounds (beyond %p)", frame, (void *)ctx->umem_sz ));

  /* Speculatively copy frame into XDP buffer */
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
  fd_memcpy( ctx->tx_op.frame, src, sz );
}

/* after_frag is called when the during_frag memcpy was _not_ overrun. */

static void
after_frag( fd_net_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)tsorig; (void)stem;

  /* Current send operation */

  uint       if_idx = ctx->tx_op.if_idx;
  uchar *    frame  = ctx->tx_op.frame;
  fd_xsk_t * xsk    = &ctx->xsk[ if_idx ];

  memcpy( frame, ctx->tx_op.mac_addrs, 12 );

  /* Submit packet TX job

     Invariant for ring_tx: prod-cons<length
     (This invariant breaks if any other packet is sent over this ring
     between before_frag and this point, e.g. send_arp_probe.) */

  fd_xdp_ring_t * tx_ring = &xsk->ring_tx;
  uint            tx_seq  = tx_ring->cached_prod;
  uint            tx_mask = tx_ring->depth - 1U;
  xsk->ring_tx.packet_ring[ tx_seq&tx_mask ] = (struct xdp_desc) {
    .addr    = (ulong)frame - (ulong)ctx->umem_frame0,
    .len     = (uint)sz,
    .options = 0
  };

  /* Frame is now owned by kernel. Clear tx_op. */
  ctx->tx_op.frame = NULL;

  /* Register newly enqueued packet */
  FD_VOLATILE( *xsk->ring_tx.prod ) = tx_ring->cached_prod = tx_seq+1U;
  ctx->metrics.tx_submit_cnt++;
  ctx->metrics.tx_bytes_total += sz;
  fd_net_flusher_inc( ctx->tx_flusher+if_idx, fd_tickcount() );

}

/* net_rx_packet is called when a new Ethernet frame is available.
   Attempts to copy out the frame to a downstream tile. */

static void
net_rx_packet( fd_net_ctx_t *      ctx,
               fd_stem_context_t * stem,
               ulong               umem_off,
               ulong               sz,
               uint *              freed_chunk,
               long                now ) {

  ulong umem_lowbits = umem_off & 0x3fUL;

  uchar const * packet     = (uchar const *)ctx->umem_frame0 + umem_off;
  uchar const * packet_end = packet + sz;
  uchar const * iphdr      = packet + 14U;

  /* Translate packet to UMEM frame index */
  ulong chunk = ctx->umem_chunk0 + (umem_off>>FD_CHUNK_LG_SZ);

  /* Filter for UDP/IPv4 packets. Test for ethtype and ipproto in 1
     branch */
  uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
  if( FD_UNLIKELY( test_ethip!=0x080011 ) ) {
    FD_LOG_ERR(( "Firedancer received a packet from the XDP program that was either "
                 "not an IPv4 packet, or not a UDP packet. It is likely your XDP program "
                 "is not configured correctly." ));
  }

  /* IPv4 is variable-length, so lookup IHL to find start of UDP */
  uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
  uchar const * udp = iphdr + iplen;

  /* Ignore if UDP header is too short */
  if( FD_UNLIKELY( udp+8U > packet_end ) ) {
    //FD_DTRACE_PROBE( net_tile_err_rx_undersz );
    ctx->metrics.rx_undersz_cnt++;
    return;
  }

  /* Extract IP dest addr and UDP src/dest port */
  uint ip_srcaddr    =                  *(uint   *)( iphdr+12UL );
  ushort udp_srcport = fd_ushort_bswap( *(ushort *)( udp+0UL    ) );
  ushort udp_dstport = fd_ushort_bswap( *(ushort *)( udp+2UL    ) );

  //FD_DTRACE_PROBE_4( net_tile_pkt_rx, ip_srcaddr, udp_srcport, udp_dstport, sz );

  /* Route packet to downstream tile */
  ushort proto;
  fd_net_out_ctx_t * out;
  if(      FD_UNLIKELY( udp_dstport==ctx->shred_listen_port ) ) {
    proto = DST_PROTO_SHRED;
    out = ctx->shred_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->quic_transaction_listen_port ) ) {
    proto = DST_PROTO_TPU_QUIC;
    out = ctx->quic_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->legacy_transaction_listen_port ) ) {
    proto = DST_PROTO_TPU_UDP;
    out = ctx->quic_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->gossip_listen_port ) ) {
    proto = DST_PROTO_GOSSIP;
    out = ctx->gossip_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->repair_intake_listen_port ) ) {
    proto = DST_PROTO_REPAIR;
    out = ctx->repair_out;
  } else if( FD_UNLIKELY( udp_dstport==ctx->repair_serve_listen_port ) ) {
    proto = DST_PROTO_REPAIR;
    out = ctx->repair_out;
  } else {

    FD_LOG_ERR(( "Firedancer received a UDP packet on port %hu which was not expected. "
                 "Only the following ports should be configured to forward packets: "
                 "%hu, %hu, %hu, %hu, %hu, %hu (excluding any 0 ports, which can be ignored)."
                 "Please report this error to Firedancer maintainers.",
                 udp_dstport,
                 ctx->shred_listen_port,
                 ctx->quic_transaction_listen_port,
                 ctx->legacy_transaction_listen_port,
                 ctx->gossip_listen_port,
                 ctx->repair_intake_listen_port,
                 ctx->repair_serve_listen_port ));
  }

  /* tile can decide how to partition based on src ip addr and src port */
  ulong sig = fd_disco_netmux_sig( ip_srcaddr, udp_srcport, 0U, proto, 14UL+8UL+iplen );

  /* Peek the mline for an old frame */
  fd_frag_meta_t * mline = out->mcache + fd_mcache_line_idx( out->seq, out->depth );
  *freed_chunk = mline->chunk;

  /* Overwrite the mline with the new frame */
  ulong tspub = (ulong)fd_frag_meta_ts_comp( now );
  fd_mcache_publish( out->mcache, out->depth, out->seq, sig, chunk, sz, umem_lowbits, 0, tspub );

  /* Wind up for the next iteration */
  *stem->cr_avail -= stem->cr_decrement_amount;
  out->seq = fd_seq_inc( out->seq, 1UL );

  ctx->metrics.rx_pkt_cnt++;
  ctx->metrics.rx_bytes_total += sz;

}

/* net_comp_event is called when an XDP TX frame is free again. */

static void
net_comp_event( fd_net_ctx_t * ctx,
                fd_xsk_t *     xsk,
                uint           comp_seq ) {

  /* Locate the incoming frame */

  fd_xdp_ring_t * comp_ring  = &xsk->ring_cr;
  uint            comp_mask  = comp_ring->depth - 1U;
  ulong           frame      = FD_VOLATILE_CONST( comp_ring->frame_ring[ comp_seq&comp_mask ] );
  ulong const     frame_mask = FD_NET_MTU - 1UL;
  if( FD_UNLIKELY( frame+FD_NET_MTU > ctx->umem_sz ) ) {
    FD_LOG_ERR(( "Bounds check failed: frame=0x%lx umem_sz=0x%lx",
                 frame, (ulong)ctx->umem_sz ));
  }

  /* Check if we have space to return the freed frame */

  fd_net_free_ring_t * free      = &ctx->free_tx;
  ulong                free_prod = free->prod;
  ulong                free_mask = free->depth - 1UL;
  long free_cnt = fd_seq_diff( free_prod, free->cons );
  if( FD_UNLIKELY( free_cnt>=(long)free->depth ) ) return; /* blocked */

  free->queue[ free_prod&free_mask ] = (ulong)ctx->umem_frame0 + (frame & (~frame_mask));
  free->prod = fd_seq_inc( free_prod, 1UL );

  /* Wind up for next iteration */

  FD_VOLATILE( *comp_ring->cons ) = comp_ring->cached_cons = comp_seq+1U;

  ctx->metrics.tx_complete_cnt++;

}

/* net_rx_event is called when a new XDP RX frame is available.  Calls
   net_rx_packet, then returns the packet back to the kernel via the fill
   ring. */

static void
net_rx_event( fd_net_ctx_t *      ctx,
              fd_stem_context_t * stem,
              fd_xsk_t *          xsk,
              long                now ) {

  // FIXME(topointon): Temporarily disabling backpressure feature because it triggers even with FD_TOPOB_UNRELIABLE
  //if( FD_UNLIKELY( *stem->cr_avail < stem->cr_decrement_amount ) ) {
  //  ctx->metrics.rx_backp_cnt++;
  //  return;
  //}

  /* Locate the incoming frame */

  fd_xdp_ring_t * rx_ring = &xsk->ring_rx;
  uint            rx_seq  = xsk->ring_rx.cached_cons;
  uint            rx_mask = rx_ring->depth - 1U;
  struct xdp_desc frame   = FD_VOLATILE_CONST( rx_ring->packet_ring[ rx_seq&rx_mask ] );

  if( FD_UNLIKELY( frame.len>FD_NET_MTU ) )
    FD_LOG_ERR(( "received a UDP packet with a too large payload (%u)", frame.len ));

  /* Check if we have space in the fill ring to free the frame */

  fd_xdp_ring_t * fill_ring  = &xsk->ring_fr;
  uint            fill_depth = fill_ring->depth;
  uint            fill_mask  = fill_depth-1U;
  ulong           frame_mask = FD_NET_MTU - 1UL;
  uint            fill_prod  = fill_ring->cached_prod;
  uint            fill_cons  = fill_ring->cached_cons;

  if( FD_UNLIKELY( (int)(fill_prod-fill_cons) >= (int)fill_depth ) ) {
    ctx->metrics.rx_fill_blocked_cnt++;
    return; /* blocked */
  }

  /* Pass it to the receive handler */

  uint freed_chunk = UINT_MAX;
  net_rx_packet( ctx, stem, frame.addr, frame.len, &freed_chunk, now );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *rx_ring->cons ) = rx_ring->cached_cons = rx_seq+1U;

  /* If this mcache publish shadowed a previous publish, mark the old
     frame as free. */

  if( FD_LIKELY( freed_chunk!=UINT_MAX ) ) {
    if( FD_UNLIKELY( ( freed_chunk < ctx->umem_chunk0 ) |
                     ( freed_chunk > ctx->umem_wmark ) ) ) {
      FD_LOG_ERR(( "mcache corruption detected: chunk=%u chunk0=%u wmark=%u",
                   freed_chunk, ctx->umem_chunk0, ctx->umem_wmark ));
    }
    ulong freed_off = (freed_chunk - ctx->umem_chunk0)<<FD_CHUNK_LG_SZ;
    fill_ring->frame_ring[ fill_prod&fill_mask ] = freed_off & (~frame_mask);
    FD_VOLATILE( *fill_ring->prod ) = fill_ring->cached_prod = fill_prod+1U;
  }

}

static void
net_tx_finish( fd_net_ctx_t * ctx ) {

  /* A memcpy was overrun during the last send attempt.  A corrupt copy
     of the packet was placed into an XDP frame, but the frame was not
     yet submitted to the TX ring.  Return tx buffer to free list. */

  if( FD_UNLIKELY( ctx->tx_op.frame ) ) {
    fd_net_free_ring_t * free      = &ctx->free_tx;
    ulong                alloc_seq = free->prod;
    free->queue[ alloc_seq % free->depth ] = (ulong)ctx->tx_op.frame;
    free->prod = fd_seq_inc( alloc_seq, 1UL );
    ctx->tx_op.frame = NULL;
  }

}
