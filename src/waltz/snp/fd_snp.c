#include "fd_snp.h"
#include "fd_snp_common.h"
#include "fd_snp_private.h"
#include "fd_snp_proto.h"

static inline int
fd_snp_conn_map_lg_slot_cnt_from_peer_cnt( ulong peer_cnt ) {
  /* 2 insertions per connection (+1) and map should have twice the capacity (+1) */
  return 2 + fd_ulong_find_msb( peer_cnt );
}

static inline int
fd_snp_dest_meta_map_lg_slot_cnt_from_peer_cnt( ulong peer_cnt ) {
  /* map should have twice the capacity (+1) */
  return 1 + fd_ulong_find_msb( peer_cnt );
}

ulong
fd_snp_footprint_ext( fd_snp_limits_t const * limits,
                      fd_snp_layout_t *       layout ) {
  memset( layout, 0, sizeof(fd_snp_layout_t) );
  if( FD_UNLIKELY( !limits ) ) return 0UL;

  if( FD_UNLIKELY( limits->peer_cnt ==0UL ) ) { FD_LOG_WARNING(( "invalid limits->peer_cnt==0" )); return 0UL; }

  layout->meta_sz = sizeof(fd_snp_layout_t);

  /* allocate space for fd_snp_t */
  ulong offs = sizeof(fd_snp_t);

  /* allocate space for connections */
  offs                      = fd_ulong_align_up( offs, fd_snp_conn_pool_align() );
  layout->conn_pool_off     = offs;
  ulong conn_pool_footprint = fd_snp_conn_pool_footprint( limits->peer_cnt );
  if( FD_UNLIKELY( !conn_pool_footprint ) ) { FD_LOG_WARNING(( "invalid fd_snp_conn_pool_footprint" )); return 0UL; }
  offs                     += conn_pool_footprint;

  /* allocate space for conn IDs */
  offs                      = fd_ulong_align_up( offs, fd_snp_conn_map_align() );
  layout->conn_map_off      = offs;
  ulong conn_map_footprint  = fd_snp_conn_map_footprint( fd_snp_conn_map_lg_slot_cnt_from_peer_cnt( limits->peer_cnt ) );
  if( FD_UNLIKELY( !conn_map_footprint  ) ) { FD_LOG_WARNING(( "invalid fd_snp_conn_map_footprint" )); return 0UL; }
  offs                     += conn_map_footprint;

  /* allocate space for packets */
  offs                      = fd_ulong_align_up( offs, fd_snp_pkt_pool_align() );
  layout->pkt_pool_off      = offs;
  ulong pkt_pool_footprint  = fd_snp_pkt_pool_footprint( limits->peer_cnt );
  if( FD_UNLIKELY( !pkt_pool_footprint  ) ) { FD_LOG_WARNING(( "invalid fd_snp_pkt_pool_footprint (pkt_pool)" )); return 0UL; }
  offs                     += pkt_pool_footprint;

  /* allocate space for connections' last packet */
  offs                      = fd_ulong_align_up( offs, fd_snp_pkt_pool_align() );
  layout->last_pkt_pool_off = offs;
  ulong last_pkt_footprint  = fd_snp_pkt_pool_footprint( limits->peer_cnt );
  if( FD_UNLIKELY( !last_pkt_footprint  ) ) { FD_LOG_WARNING(( "invalid fd_snp_pkt_pool_footprint (last_pkt_pool)" )); return 0UL; }
  offs                     += last_pkt_footprint;

  /* allocate space for dest_meta maps (a,b) */
  offs                            = fd_ulong_align_up( offs, fd_snp_dest_meta_map_align() );
  layout->dest_meta_map_off_a     = offs;
  ulong dest_meta_map_footprint_a = fd_snp_dest_meta_map_footprint( fd_snp_dest_meta_map_lg_slot_cnt_from_peer_cnt( limits->peer_cnt ) );
  if( FD_UNLIKELY( !dest_meta_map_footprint_a ) ) { FD_LOG_WARNING(( "invalid fd_snp_dest_meta_map_footprint a" )); return 0UL; }
  offs                           += dest_meta_map_footprint_a;

  offs                            = fd_ulong_align_up( offs, fd_snp_dest_meta_map_align() );
  layout->dest_meta_map_off_b     = offs;
  ulong dest_meta_map_footprint_b = fd_snp_dest_meta_map_footprint( fd_snp_dest_meta_map_lg_slot_cnt_from_peer_cnt( limits->peer_cnt ) );
  if( FD_UNLIKELY( !dest_meta_map_footprint_b ) ) { FD_LOG_WARNING(( "invalid fd_snp_dest_meta_map_footprint b" )); return 0UL; }
  offs                           += dest_meta_map_footprint_b;

  return offs;
}

ulong
fd_snp_footprint( fd_snp_limits_t const * limits ) {
  fd_snp_layout_t layout;
  return fd_snp_footprint_ext( limits, &layout );
}

void *
fd_snp_new( void* mem,
            fd_snp_limits_t const * limits ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  ulong align = fd_snp_align();
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, align ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !limits ) ) {
    FD_LOG_WARNING(( "NULL limits" ));
    return NULL;
  }

  if( FD_UNLIKELY( limits->peer_cnt == 0UL ) ) {
    FD_LOG_WARNING(( "invalid limits" ));
    return NULL;
  }

  fd_snp_layout_t layout;
  ulong footprint = fd_snp_footprint_ext( limits, &layout );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "invalid footprint for config" ));
    return NULL;
  }

  /* Zero the entire memory region */
  fd_snp_t * snp = (fd_snp_t *)mem;
  memset( snp, 0, fd_snp_footprint( limits ) );

  /* Store the limits */
  snp->limits = *limits;
  snp->layout = layout;

  /* Set magic number to indicate successful initialization */
  FD_COMPILER_MFENCE();
  snp->magic = FD_SNP_MAGIC;
  FD_COMPILER_MFENCE();

  return snp;
}

fd_snp_t *
fd_snp_join( void* shsnp ) {
  return shsnp;
}

fd_snp_t *
fd_snp_init( fd_snp_t * snp ) {

  fd_snp_limits_t const * limits = &snp->limits;

  /* Validate layout */
  fd_snp_layout_t layout = {0};
  if( FD_UNLIKELY( !fd_snp_footprint_ext( limits, &layout ) ) ) {
    FD_LOG_WARNING(( "fd_snp_footprint_ext failed" ));
  }
  if( FD_UNLIKELY( 0!=memcmp( &layout, &snp->layout, sizeof(fd_snp_layout_t) ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "saved layout",   &snp->layout, sizeof(fd_snp_layout_t) ));
    FD_LOG_HEXDUMP_WARNING(( "derived layout", &layout,      sizeof(fd_snp_layout_t) ));
    FD_LOG_WARNING(( "fd_snp_layout changed. Memory corruption?" ));
  }

  /* Initialize apps (statically allocated) */
  if( FD_UNLIKELY( snp->apps_cnt > FD_SNP_APPS_CNT_MAX ) ) {
    FD_LOG_WARNING(( "invalid apps_cnt=%lu max=%lu", snp->apps_cnt, FD_SNP_APPS_CNT_MAX ));
    return NULL;
  }
  for( ulong j=0; j<snp->apps_cnt; j++ ) {
    if( FD_UNLIKELY( snp->apps[j].port==0 ) ) {
      FD_LOG_WARNING(( "invalid apps[%lu].port=%hu", j, snp->apps[j].port ));
      return NULL;
    }
    fd_ip4_udp_hdr_init( snp->apps[j].net_hdr, 0, 0, snp->apps[j].port );
    snp->apps[j].multicast_net_hdr[j]              = snp->apps[j].net_hdr[j];
    snp->apps[j].multicast_net_hdr->ip4->daddr     = fd_uint_bswap( snp->apps[j].multicast_ip );
    snp->apps[j].multicast_net_hdr->udp->net_dport = fd_ushort_bswap( snp->apps[j].port );
  }

  /* Initialize conn_pool */
  uchar * conn_pool_laddr = (uchar *)snp + layout.conn_pool_off;
  snp->conn_pool = fd_snp_conn_pool_join( fd_snp_conn_pool_new( conn_pool_laddr, limits->peer_cnt ) );
  if( FD_UNLIKELY( !snp->conn_pool ) ) {
    FD_LOG_WARNING(( "NULL conn_pool" ));
    return NULL;
  }

  /* Initialize conn_map */
  uchar * conn_map_laddr = (uchar *)snp + layout.conn_map_off;
  snp->conn_map = fd_snp_conn_map_join( fd_snp_conn_map_new( (void *)conn_map_laddr, fd_snp_conn_map_lg_slot_cnt_from_peer_cnt( limits->peer_cnt ) ) );
  if( FD_UNLIKELY( !snp->conn_map ) ) {
    FD_LOG_WARNING(( "NULL conn_map" ));
    return NULL;
  }

  /* Initialize pkt_pool */
  uchar * pkt_pool_laddr = (uchar *)snp + layout.pkt_pool_off;
  snp->pkt_pool = fd_snp_pkt_pool_join( fd_snp_pkt_pool_new( pkt_pool_laddr, limits->peer_cnt ) );
  if( FD_UNLIKELY( !snp->pkt_pool ) ) {
    FD_LOG_WARNING(( "NULL pkt_pool" ));
    return NULL;
  }

  /* Initialize last_pkt_pool */
  uchar * last_pkt_pool_laddr = (uchar *)snp + layout.last_pkt_pool_off;
  snp->last_pkt_pool = fd_snp_pkt_pool_join( fd_snp_pkt_pool_new( last_pkt_pool_laddr, limits->peer_cnt ) );
  if( FD_UNLIKELY( !snp->last_pkt_pool ) ) {
    FD_LOG_WARNING(( "NULL last_pkt_pool" ));
    return NULL;
  }

  /* Initialize private state */
  fd_rng_join( fd_rng_new( snp->config._rng, (uint)fd_tickcount(), 0UL ) );
  uchar random_aes_key[ 16 ] = { 0 };
  fd_snp_rng( random_aes_key, 16 );
  fd_aes_set_encrypt_key( random_aes_key, 128, snp->config._state_enc_key );
  fd_aes_set_decrypt_key( random_aes_key, 128, snp->config._state_dec_key );

  /* Initialize flow control credits pool (to zero). */
  if( FD_UNLIKELY( !snp->flow_cred_total ) ) { /* must be set externally. */
    snp->flow_cred_total = 1L;
    FD_LOG_WARNING(( "snp flow_cred_total uninitialized setting to %ld", snp->flow_cred_total ));
  }
  snp->flow_cred_taken = 0L;
  if( FD_UNLIKELY( !snp->flow_cred_alloc ) ) { /* must be set externally. */
    snp->flow_cred_alloc = 1L;
    FD_LOG_WARNING(( "snp flow_cred_alloc uninitialized setting to %ld", snp->flow_cred_alloc ));
  }

  /* Initialize dest_meta_map */
  uchar * dest_meta_map_laddr_a = (uchar *)snp + layout.dest_meta_map_off_a;
  snp->dest_meta_map_a = fd_snp_dest_meta_map_join( fd_snp_dest_meta_map_new( (void *)dest_meta_map_laddr_a, fd_snp_dest_meta_map_lg_slot_cnt_from_peer_cnt( limits->peer_cnt ) ) );
  if( FD_UNLIKELY( !snp->dest_meta_map_a ) ) {
    FD_LOG_WARNING(( "NULL dest_meta_map_a" ));
    return NULL;
  }
  uchar * dest_meta_map_laddr_b = (uchar *)snp + layout.dest_meta_map_off_b;
  snp->dest_meta_map_b = fd_snp_dest_meta_map_join( fd_snp_dest_meta_map_new( (void *)dest_meta_map_laddr_b, fd_snp_dest_meta_map_lg_slot_cnt_from_peer_cnt( limits->peer_cnt ) ) );
  if( FD_UNLIKELY( !snp->dest_meta_map_b ) ) {
    FD_LOG_WARNING(( "NULL dest_meta_map_b" ));
    return NULL;
  }
  snp->dest_meta_map   = snp->dest_meta_map_a;
  snp->dest_meta_update_idx      = 0U;
  snp->dest_meta_next_update_ts  = 0UL;

  snp->rng = fd_rng_join( fd_rng_new( snp->rng_mem, (uint)fd_tickcount() /*seed*/, 0UL ) );

  memset( snp->metrics_all, 0, sizeof(fd_snp_metrics_t) );
  memset( snp->metrics_enf, 0, sizeof(fd_snp_metrics_t) );

  return snp;
}

fd_snp_t *
fd_snp_fini( fd_snp_t* snp ) {
  return snp;
}

/* Connections */

#define FD_SNP_MAX_SESSION_ID_RETRIES (10)

/* fd_snp_conn_zeroize zeroes out a fd_snp_conn_t struct.
   Because fd_snp_conn_t implements a fd_pool, we need to save
   the field next before zeroing out, and restore it after.
   We use fd_memset_explicit() to make sure key material is erased. */
void
fd_snp_conn_zeroize( fd_snp_conn_t * conn ) {
  ulong next = conn->next;
  fd_memset_explicit( conn, 0, sizeof(fd_snp_conn_t) );
  conn->next = next;
}

/* fd_snp_conn_create a new fd_snp_conn_t struct from the snp pool,
   and inserts in the snp map by peer_addr and by session_id. */
static inline fd_snp_conn_t *
fd_snp_conn_create( fd_snp_t * snp,
                    ulong      peer_addr,
                    uchar      is_server ) {
  fd_snp_conn_map_t * entry = NULL;
  ulong session_id = 0UL;
  int i = 0;

  /* get a new conn from pool */
  if( FD_UNLIKELY( !fd_snp_conn_pool_free( snp->conn_pool ) ) ) {
    FD_SNP_LOG_DEBUG_W( "unable to find space in connection pool" );
    return NULL;
  }
  fd_snp_conn_t * conn = fd_snp_conn_pool_ele_acquire( snp->conn_pool );
  if( FD_UNLIKELY( conn==NULL ) ) {
    FD_SNP_LOG_DEBUG_W( "unable to acquire element from connection pool" );
    return NULL;
  }

  /* get a new last_pkt from pool */
  if( FD_UNLIKELY( !fd_snp_pkt_pool_free( snp->last_pkt_pool ) ) ) {
    FD_SNP_LOG_DEBUG_W( "unable to find space in packet pool" );
    return NULL;
  }
  fd_snp_pkt_t * last_pkt = fd_snp_pkt_pool_ele_acquire( snp->last_pkt_pool );
  if( FD_UNLIKELY( last_pkt==NULL ) ) {
    FD_SNP_LOG_DEBUG_W( "unable to acquire element from packet pool" );
    goto err;
  }

  /* insert conn in map by peer_addr. ignore failure.
     if this fails, there's already a conn for peer_addr. */
  entry = fd_snp_conn_map_insert( snp->conn_map, peer_addr );
  if( FD_LIKELY( entry ) ) {
    entry->val = conn;
  }

  /* insert conn in map by session_id. do NOT ignore failure.
     session_id is randomly generated, in case of failure we
     retry FD_SNP_MAX_SESSION_ID_RETRIES times, then fail. */
  for( i=0, entry=NULL; i<FD_SNP_MAX_SESSION_ID_RETRIES && entry==NULL; i++ ) {
    session_id = fd_rng_ulong( snp->config._rng );
    entry = fd_snp_conn_map_insert( snp->conn_map, session_id );
  }
  if( FD_LIKELY( entry ) ) {
    entry->val = conn;
  } else {
    /* fd_snp_conn_map_insert(..., sessio_id) failed n times */
    FD_SNP_LOG_DEBUG_W( "unable to generate a unique session_id" );
    goto err;
  }
  FD_SNP_LOG_DEBUG_N( "fd_snp_conn_create is_server=%u %s", is_server, FD_SNP_LOG_CONN( conn ) );

  /* init conn */
  fd_snp_conn_zeroize( conn );
  conn->peer_addr = peer_addr;
  conn->session_id = session_id;
  conn->state = FD_SNP_TYPE_INVALID;
  conn->last_pkt = last_pkt;
  conn->_pubkey = snp->config.identity;
  conn->is_server = is_server;
  /* Currently, every connection is allocated the same  amount
     of credits.  In the future, however, it may be possible
     to allocate more credits to specific connections. */
  snp->flow_cred_taken += snp->flow_cred_alloc;
  conn->flow_rx_alloc = snp->flow_cred_alloc;
  conn->flow_rx_level = 0L;
  conn->flow_rx_wmark = snp->flow_cred_alloc;
  conn->flow_rx_wmark_tstamp = fd_snp_timestamp_ms();
  conn->flow_tx_level = 0L;
  conn->flow_tx_wmark = LONG_MAX; /* This prevents any kind of deadlocks on startup.*/

  conn->is_multicast = 0;

  conn->snp_enabled  = 0;
  conn->snp_enforced = 0;
  ulong dest_meta_map_key = fd_snp_dest_meta_map_key_from_conn( conn );
  fd_snp_dest_meta_map_t sentinel = { 0 };
  fd_snp_dest_meta_map_t * dest_meta = fd_snp_dest_meta_map_query( snp->dest_meta_map, dest_meta_map_key, &sentinel );
  if( !!entry->key ) {
    conn->snp_enabled   = dest_meta->val.snp_enabled;
    conn->snp_enforced  = dest_meta->val.snp_enforced;
  }

  conn->last_sent_ts = fd_snp_timestamp_ms();

  /* init last_pkt */
  last_pkt->data_sz = 0;

  /* metrics */
  snp->metrics_all->conn_acc_total += 1UL;
  if( !!conn->snp_enforced ) {
    snp->metrics_enf->conn_cur_total += 1UL;
    snp->metrics_enf->conn_acc_total += 1UL;
  }

  return conn;

err:
  if( last_pkt ) {
    fd_snp_pkt_pool_ele_release( snp->last_pkt_pool, last_pkt );
  }
  if( conn ) {
    fd_snp_conn_pool_ele_release( snp->conn_pool, conn );
  }
  return NULL;
}

int
fd_snp_conn_delete( fd_snp_t * snp,
                    fd_snp_conn_t * conn ) {
  /* return taken flow credits to the pool. */
  snp->flow_cred_taken -= conn->flow_rx_alloc;

  /* metrics */
  snp->metrics_all->conn_cur_established   -= fd_ulong_if( conn->state==FD_SNP_TYPE_HS_DONE, 1UL, 0UL );
  snp->metrics_all->conn_acc_dropped       += 1UL;
  if( !!conn->snp_enforced ) {
    snp->metrics_enf->conn_cur_total       -= 1UL;
    snp->metrics_enf->conn_cur_established -= fd_ulong_if( conn->state==FD_SNP_TYPE_HS_DONE, 1UL, 0UL );
    snp->metrics_enf->conn_acc_dropped     += 1UL;
  }

  if( snp->last_pkt_pool ) {
    fd_snp_pkt_pool_ele_release( snp->last_pkt_pool, conn->last_pkt );
  }

  fd_snp_conn_map_t sentinel = { 0 };
  fd_snp_conn_map_t * entry0 = fd_snp_conn_map_query( snp->conn_map, conn->peer_addr, &sentinel );
  if( entry0->val && entry0->val->session_id==conn->session_id ) {
    fd_snp_conn_map_remove( snp->conn_map, entry0 );
  }
  fd_snp_conn_map_t * entry1 = fd_snp_conn_map_query( snp->conn_map, conn->session_id, &sentinel );
  if( entry1->val ) {
    fd_snp_conn_map_remove( snp->conn_map, entry1 );
  }

  fd_snp_conn_zeroize( conn );
  fd_snp_conn_pool_ele_release( snp->conn_pool, conn );
  return 0;
}

static inline fd_snp_conn_t *
fd_snp_conn_query( fd_snp_t * snp,
                   ulong      session_id ) {
  if( FD_UNLIKELY( !session_id ) ) {
    return NULL;
  }
  fd_snp_conn_map_t sentinel = { 0 };
  fd_snp_conn_map_t * entry = fd_snp_conn_map_query( snp->conn_map, session_id, &sentinel );
  return entry->val;
}

static inline fd_snp_conn_t *
fd_snp_conn_query_by_peer( fd_snp_t * snp,
                           ulong      peer_addr ) {
  if( FD_UNLIKELY( !peer_addr ) ) {
    return NULL;
  }
  fd_snp_conn_map_t sentinel = { 0 };
  fd_snp_conn_map_t * entry = fd_snp_conn_map_query( snp->conn_map, peer_addr, &sentinel );
  return entry->val;
}

static inline int
fd_snp_has_enough_flow_tx_credit( fd_snp_t *      snp,
                                  fd_snp_conn_t * conn ) {
  (void)snp;
  /* Returns true if there are enough flow tx credits to send a
     packet.  It does not take responses into account (e.g.
     ACKs), in which case one should also check flow_rx_level.
     The receiver guarantees that there are FD_SNP_MTU bytes
     available beyond the watermark, which may be crossed only
     once per watermark value.  This minimizes the calculations
     around the crossing boundary and avoids weird edge cases. */
  int has_enough_tx_credit = conn->flow_tx_level < conn->flow_tx_wmark;
  return has_enough_tx_credit;
}

static inline int
fd_snp_has_enough_flow_rx_credit( fd_snp_t *      snp FD_PARAM_UNUSED,
                                  fd_snp_conn_t * conn ) {
  /* Returns true if there are enough flow rx credits to receive
     a packet.  It does not take responses into account (e.g.
     ACKs), in which case one should also check flow_tx_level.
     The receiver guarantees that there are FD_SNP_MTU bytes
     available beyond the watermark, which may be crossed only
     once per watermark value.  This minimizes the calculations
     around the crossing boundary and avoids weird edge cases. */
  int has_enough_rx_credit = conn->flow_rx_level < conn->flow_rx_wmark;
  return has_enough_rx_credit;
}

static inline void
fd_snp_incr_flow_tx_level( fd_snp_t *      snp FD_PARAM_UNUSED,
                           fd_snp_conn_t * conn,
                           ulong           incr ) {
  conn->flow_tx_level += (long)incr;
}

static inline void
fd_snp_incr_flow_rx_level( fd_snp_t *      snp FD_PARAM_UNUSED,
                           fd_snp_conn_t * conn,
                           ulong           incr ) {
  conn->flow_rx_level += (long)incr;
}

static inline int
fd_snp_finalize_udp_and_invoke_tx_cb(
  fd_snp_t *      snp,
  uchar *         packet,
  ulong           packet_sz,
  fd_snp_meta_t   meta,
  fd_snp_conn_t * opt_conn
) {
  if( FD_UNLIKELY( packet_sz==0 ) ) {
    return 0;
  }

  uchar snp_app_id;
  ushort dst_port;
  uint dst_ip;
  fd_snp_meta_into_parts( NULL, &snp_app_id, &dst_ip, &dst_port, meta );

  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  *hdr = *( snp->apps[ snp_app_id ].net_hdr );
  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->daddr  = dst_ip;
  ip4->net_id = fd_ushort_bswap( snp->apps[ snp_app_id ].net_id++ );
  ip4->net_tot_len  = fd_ushort_bswap( (ushort)(packet_sz - sizeof(fd_eth_hdr_t)) );
  ip4->check  = fd_ip4_hdr_check_fast( ip4 );
  hdr->udp->net_dport  = fd_ushort_bswap( dst_port );
  hdr->udp->net_len    = fd_ushort_bswap( (ushort)( packet_sz - sizeof(fd_ip4_udp_hdrs_t) + sizeof(fd_udp_hdr_t) ) );

  if( !!opt_conn ) {
    opt_conn->last_sent_ts = fd_snp_timestamp_ms();
  }

  /* metrics */
  if( !!opt_conn ) {
    snp->metrics_all->tx_bytes_via_snp_cnt += packet_sz;
    snp->metrics_all->tx_pkts_via_snp_cnt  += 1UL;
    if( !!opt_conn->snp_enforced ) {
      snp->metrics_enf->tx_bytes_via_snp_cnt += packet_sz;
      snp->metrics_enf->tx_pkts_via_snp_cnt  += 1UL;
    }
  } else {
    snp->metrics_all->tx_bytes_via_udp_cnt += packet_sz;
    snp->metrics_all->tx_pkts_via_udp_cnt  += 1UL;
  }

  return snp->cb.tx ? snp->cb.tx( snp->cb.ctx, packet, packet_sz, meta ) : (int)packet_sz;
}

static inline int
fd_snp_finalize_snp_and_invoke_tx_cb(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  uchar *         packet,
  ulong           packet_sz,
  fd_snp_meta_t   meta,
  int             flow_tx_credit_bypass
) {
  if( FD_UNLIKELY( packet_sz==0 ) ) {
    return 0;
  }
  if( FD_UNLIKELY( !flow_tx_credit_bypass && !fd_snp_has_enough_flow_tx_credit( snp, conn ) ) ) {
    /* metrics */
    snp->metrics_all->tx_pkts_dropped_no_credits_cnt += 1UL;
    if( !!conn->snp_enforced ) {
      snp->metrics_enf->tx_pkts_dropped_no_credits_cnt += 1UL;
    }
    FD_SNP_LOG_DEBUG_W( "[snp-finalize] unable to send snp pkt due to insufficient flow tx credits %s", FD_SNP_LOG_CONN( conn ) );
    return -1;
  }
  fd_snp_incr_flow_tx_level( snp, conn, packet_sz );
  fd_snp_v1_finalize_packet( conn, packet+sizeof(fd_ip4_udp_hdrs_t), packet_sz-sizeof(fd_ip4_udp_hdrs_t) );

  return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta & (~FD_SNP_META_OPT_HANDSHAKE), conn );
}

static inline void
fd_snp_update_rx_metrics( fd_snp_t *               snp,
                          ulong                    packet_sz,
                          fd_snp_meta_t            meta,
                          fd_snp_conn_t *          opt_conn,
                          fd_snp_dest_meta_map_t * dest_meta ) {
  /* in this function, meta is set with FD_SNP_META_PROTO_UDP or SNP.
     in the UDP case, opt_conn is always NULL.
     in the SNP case, opt_conn can be NULL.
     in both cases dest_meta was already queried,
     but dest_meta->key could be NULL. */
  if( ( meta & FD_SNP_META_PROTO_MASK ) == FD_SNP_META_PROTO_UDP ) {
    /* UDP */
    snp->metrics_all->rx_bytes_via_udp_cnt += packet_sz;
    snp->metrics_all->rx_pkts_via_udp_cnt  += 1UL;

    if( FD_UNLIKELY( dest_meta->key && dest_meta->val.snp_enforced ) ) {
      /* This should never happen, but we increase the metric to track it. */
      snp->metrics_enf->rx_bytes_via_udp_cnt += packet_sz;
      snp->metrics_enf->rx_pkts_via_udp_cnt  += 1UL;
    }
  } else {
    /* SNP */
    snp->metrics_all->rx_bytes_via_snp_cnt += packet_sz;
    snp->metrics_all->rx_pkts_via_snp_cnt  += 1UL;

    /* enforced can come either from conn (when not NULL),
       or from dest_meta (when key is not NULL). */
    int is_enforced = ( opt_conn && opt_conn->snp_enforced )
      || ( dest_meta->key && dest_meta->val.snp_enforced );

    if( is_enforced ) {
      snp->metrics_enf->rx_bytes_via_snp_cnt += packet_sz;
      snp->metrics_enf->rx_pkts_via_snp_cnt  += 1UL;
    }
  }
}

static inline int
fd_snp_verify_snp_and_invoke_rx_cb(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  uchar *         packet,
  ulong           packet_sz,
  fd_snp_meta_t   meta
) {
  /* Process wmark updates first. */
  tlv_meta_t tlv[1];
  ulong off = sizeof(fd_ip4_udp_hdrs_t) + sizeof(snp_hdr_t);
  off       = fd_snp_tlv_extract_fast( packet, off, tlv );
  /* This assumes that every wmark update is sent in a separate packet. */
  if( FD_UNLIKELY( tlv[0].type==FD_SNP_FRAME_MAX_DATA ) ) {
    int res = fd_snp_v1_validate_packet( conn, packet+sizeof(fd_ip4_udp_hdrs_t), packet_sz-sizeof(fd_ip4_udp_hdrs_t) );
    if( FD_UNLIKELY( res < 0 ) ) {
      FD_SNP_LOG_DEBUG_W( "[snp-pkt] tlv type %u fd_snp_v1_validate_packet failed with res %d %s", tlv[0].type, res, FD_SNP_LOG_CONN( conn ) );
      return -1;
    }
    do {
      if( tlv[0].len==8U ) {
        long wmark = (long)fd_ulong_load_8( tlv[0].ptr + 0UL );
        FD_SNP_LOG_TRACE( "[snp-pkt] tlv type %u wmark prev %ld new %ld %s", tlv[0].type, conn->flow_tx_wmark, wmark, FD_SNP_LOG_CONN( conn ) );
        conn->flow_tx_wmark = wmark;
      } else if( tlv[0].len==16U ) {
        long wmark = (long)fd_ulong_load_8( tlv[0].ptr + 0UL );
        long level = (long)fd_ulong_load_8( tlv[0].ptr + 8UL );
        FD_SNP_LOG_TRACE( "[snp-pkt] tlv type %u wmark prev %ld new %ld level prev %ld new %ld %s", tlv[0].type, conn->flow_tx_wmark, wmark, conn->flow_tx_level, level, FD_SNP_LOG_CONN( conn ) );
        conn->flow_tx_wmark = wmark;
        /* This is not 100% accurate, since pkts may still be in flight when the
           current level was sampled by the reciver, but this is acceptable. */
        conn->flow_tx_level = level; /* It does its best to resync if pkts have been lost. */
      } else {
        FD_SNP_LOG_DEBUG_W( "[snp-pkt] tlv type %u len %u mismatch! %s", tlv[0].type, tlv[0].len, FD_SNP_LOG_CONN( conn ) );
        return -1;
      }
      off = fd_snp_tlv_extract_fast( packet, off, tlv );
    } while( tlv[0].type==FD_SNP_FRAME_MAX_DATA );
    conn->last_recv_ts = fd_snp_timestamp_ms();
    return 0;
  }

  /* Process any other packet. */
  if( FD_UNLIKELY( !fd_snp_has_enough_flow_rx_credit( snp, conn ) ) ) {
    /* metrics */
    snp->metrics_all->rx_pkts_dropped_no_credits_cnt += 1UL;
    if( !!conn->snp_enforced ) {
      snp->metrics_enf->rx_pkts_dropped_no_credits_cnt += 1UL;
    }
    FD_SNP_LOG_DEBUG_W( "[snp-verify] unable to verify snp pkt due to insufficient flow rx credits %s", FD_SNP_LOG_CONN( conn ) );
    return -1;
  }
  fd_snp_incr_flow_rx_level( snp, conn, packet_sz );
  int res = fd_snp_v1_validate_packet( conn, packet+sizeof(fd_ip4_udp_hdrs_t), packet_sz-sizeof(fd_ip4_udp_hdrs_t) );
  if( FD_UNLIKELY( res < 0 ) ) {
    FD_SNP_LOG_DEBUG_W( "[snp-verify] validate packet failed with res=%d %s", res, FD_SNP_LOG_CONN( conn ) );
    return res;
  }

  conn->last_recv_ts = fd_snp_timestamp_ms();
  ulong data_offset = sizeof(fd_ip4_udp_hdrs_t) + 12;
  if( FD_LIKELY( packet[data_offset]==FD_SNP_FRAME_DATAGRAM ) ) {
    return snp->cb.rx( snp->cb.ctx, packet, packet_sz, meta );
  } else if( FD_LIKELY( packet[data_offset]==FD_SNP_FRAME_PING ) ) {
    FD_SNP_LOG_DEBUG_N( "[snp] received PING %s", FD_SNP_LOG_CONN( conn ) );
    return 0;
  }
  FD_SNP_LOG_DEBUG_W( "[snp-verify] nothing to do!? %s", FD_SNP_LOG_CONN( conn ) );
  return 0;
}

static inline int
fd_snp_finalize_multicast_and_invoke_tx_cb(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn FD_PARAM_UNUSED,
  uchar *         packet,
  ulong           packet_sz,
  fd_snp_meta_t   meta
) {
  if( FD_UNLIKELY( packet_sz==0 ) ) {
    return 0;
  }

  /* no mac auth */
  packet_sz -= 19UL;

  /* snp header */
  snp_hdr_t * udp_payload = (snp_hdr_t *)( packet + sizeof(fd_ip4_udp_hdrs_t) );
  udp_payload->version_type = fd_snp_hdr_version_type( FD_SNP_V1, FD_SNP_TYPE_PAYLOAD );
  udp_payload->session_id = 0UL;

  /* ip header */
  uchar snp_app_id;
  fd_snp_meta_into_parts( NULL, &snp_app_id, NULL, NULL, meta );

  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  memcpy( hdr, snp->apps[ snp_app_id ].multicast_net_hdr, sizeof(fd_ip4_udp_hdrs_t) );
  fd_ip4_hdr_t * ip4 = hdr->ip4;
  ip4->net_id       = fd_ushort_bswap( snp->apps[ snp_app_id ].net_id++ );
  ip4->net_tot_len  = fd_ushort_bswap( (ushort)(packet_sz - sizeof(fd_eth_hdr_t)) );
  ip4->check        = fd_ip4_hdr_check_fast( ip4 );
  hdr->udp->net_len = fd_ushort_bswap( (ushort)( packet_sz - sizeof(fd_ip4_udp_hdrs_t) + sizeof(fd_udp_hdr_t) ) );

  return snp->cb.tx ? snp->cb.tx( snp->cb.ctx, packet, packet_sz, meta ) : (int)packet_sz;
}

static inline int
fd_snp_cache_packet_and_invoke_sign_cb(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  uchar *         packet,
  int             packet_snp_sz, /* without headers */
  uchar *         to_sign
) {
  if( FD_LIKELY( packet_snp_sz > 0 ) ) {
    conn->last_pkt->data_sz = (ushort)((ulong)packet_snp_sz+sizeof(fd_ip4_udp_hdrs_t));
    memcpy( conn->last_pkt->data, packet, conn->last_pkt->data_sz );
    return snp->cb.sign( snp->cb.ctx, conn->session_id, to_sign );
  }
  return packet_snp_sz;
}

int
fd_snp_cache_packet_for_retry( fd_snp_conn_t * conn,
                               uchar const *   packet,
                               ulong           packet_sz,
                               fd_snp_meta_t   meta ) {
  if( FD_UNLIKELY( conn==NULL || conn->last_pkt==NULL ) ) {
    return -1;
  }
  conn->retry_cnt = 0;
  memcpy( conn->last_pkt->data, packet, packet_sz );
  conn->last_pkt->data_sz = (ushort)packet_sz;
  conn->last_pkt->meta = meta;
  return 0;
}

int
fd_snp_retry_cached_packet( fd_snp_t *      snp,
                            fd_snp_conn_t * conn ) {
  uchar * packet = conn->last_pkt->data;
  ulong   packet_sz = conn->last_pkt->data_sz;
  fd_snp_meta_t meta = conn->last_pkt->meta;
  return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta | FD_SNP_META_OPT_BUFFERED, conn );
}

int
fd_snp_send_ping( fd_snp_t *      snp,
                  fd_snp_conn_t * conn ) {
  uchar packet[ FD_SNP_MTU ] = { 0 };

  /* PING */
  ulong data_offset = sizeof(fd_ip4_udp_hdrs_t) + 12;
  if( FD_LIKELY( packet!=NULL ) ) {
    packet[data_offset] = FD_SNP_FRAME_PING;
    ushort data_sz_h = (ushort)0;
    memcpy( packet+data_offset+1, &data_sz_h, 2 );
  }
  data_offset += 3;

  ulong packet_sz = 0 + data_offset + 19;
  fd_snp_meta_t meta = conn->peer_addr | FD_SNP_META_PROTO_V1;
  return fd_snp_finalize_snp_and_invoke_tx_cb( snp, conn, packet, packet_sz, meta | FD_SNP_META_OPT_BUFFERED, 0/*flow_tx_credit_bypass*/ );
}

static inline int
fd_snp_pkt_pool_store( fd_snp_t *            snp,
                       fd_snp_conn_t const * conn,
                       uchar const *         packet,
                       ulong                 packet_sz,
                       uchar                 send ) {
  if( FD_UNLIKELY( !fd_snp_pkt_pool_free( snp->pkt_pool ) ) ) {
    return -1;
  }
  fd_snp_pkt_t * pkt = fd_snp_pkt_pool_ele_acquire( snp->pkt_pool );
  if( FD_LIKELY( pkt ) ) {
    pkt->session_id = conn->session_id;
    memcpy( pkt->data, packet, packet_sz );
    pkt->data_sz = (ushort)packet_sz;
    pkt->send = send;
  }
  return 0;
}

static inline void
fd_snp_pkt_pool_process(
  fd_snp_t *      snp,
  fd_snp_conn_t * conn,
  fd_snp_meta_t   meta
) {
  ulong meta_buffered = ( meta | FD_SNP_META_OPT_BUFFERED );
  ulong max  = fd_snp_pkt_pool_max( snp->pkt_pool );
  ulong used = fd_snp_pkt_pool_used( snp->pkt_pool );
  ulong idx = 0;
  ulong used_ele = 0;
  fd_snp_pkt_t * ele = snp->pkt_pool;
  for( ; idx<max; idx++, ele++ ) {
    if( ele->session_id == 0 ) continue;
    if( ele->session_id == conn->session_id ) {
      uchar * buf    = ele->data;
      ulong   buf_sz = (ulong)ele->data_sz;

      /* ignore return from callbacks for cached packets */
      FD_PARAM_UNUSED int res = 0;
      if( ele->send==1 ) {
        res = fd_snp_finalize_snp_and_invoke_tx_cb( snp, conn, buf, buf_sz, meta_buffered, 0/*flow_tx_credit_bypass*/ );
      } else {
        res = fd_snp_verify_snp_and_invoke_rx_cb( snp, conn, buf, buf_sz, meta_buffered );
      }

      /* delete cached packet */
      ele->session_id = 0;
      fd_snp_pkt_pool_idx_release( snp->pkt_pool, idx );

      if( res<0 ) { FD_SNP_LOG_DEBUG_W( "[snp-pool] unable to process cached packet ele->send=%u %s", ele->send, FD_SNP_LOG_CONN( conn ) ); }
    }
    if( ++used_ele>=used ) break;
  }
}

static inline int
fd_snp_send_flow_rx_wmark_packet( fd_snp_t *      snp,
                                  fd_snp_conn_t * conn ) {
  uchar packet[1514];
  const ulong off = sizeof(fd_ip4_udp_hdrs_t) + sizeof(snp_hdr_t);
  const ulong packet_sz = off + (1UL+2UL+8UL)/*tlv with wmark */ + (1UL+2UL+8UL+8UL)/*tlv with wmark and level */ + (1UL+2UL+16UL)/*hmac*/;
  fd_snp_meta_t meta = conn->peer_addr | FD_SNP_META_PROTO_V1;
  /* backward compatible format */
  packet [off + 0UL ] = FD_SNP_FRAME_MAX_DATA;
  FD_STORE( ushort, packet + off + 1UL, 8U );
  FD_STORE(   long, packet + off + 3UL, conn->flow_rx_wmark );
  /* new format */
  packet [off + 11UL ] = FD_SNP_FRAME_MAX_DATA;
  FD_STORE( ushort, packet + off + 12UL, 16U );
  FD_STORE(   long, packet + off + 14UL, conn->flow_rx_wmark );
  FD_STORE(   long, packet + off + 22UL, conn->flow_rx_level );
  conn->flow_rx_wmark_tstamp = fd_snp_timestamp_ms();
  return fd_snp_finalize_snp_and_invoke_tx_cb( snp, conn, packet, packet_sz, meta | FD_SNP_META_OPT_BUFFERED, 1/*flow_tx_credit_bypass*/ );
}

static inline void
fd_snp_dest_meta_map_update_on_handshake( fd_snp_t *      snp,
                                          fd_snp_conn_t * conn ) {
  FD_TEST( snp );
  uint   ip4_addr = 0;
  ushort udp_port = 0;
  fd_snp_peer_addr_into_parts( &ip4_addr, &udp_port, conn->peer_addr );
  ulong key = fd_snp_dest_meta_map_key_from_conn( conn );
  fd_snp_dest_meta_map_t sentinel = { 0 };
  fd_snp_dest_meta_map_t * entry = fd_snp_dest_meta_map_query( snp->dest_meta_map, key, &sentinel );
  int is_new = 0;
  if( FD_UNLIKELY( !entry->key ) ) {
    entry = fd_snp_dest_meta_map_insert( snp->dest_meta_map, key );
    is_new = 1;
  }
  if( FD_UNLIKELY( is_new ) ) {
    entry->val.ip4_addr    = ip4_addr;
    entry->val.udp_port    = udp_port;
  }
  entry->val.update_idx    = snp->dest_meta_update_idx;
  entry->val.snp_available = 1;
  entry->val.snp_enabled   = 1;

  FD_SNP_LOG_DEBUG_N( "%u.%u.%u.%u:%u snp_available %x snp_enabled %x %s",
    (entry->val.ip4_addr>>0)&0xff, (entry->val.ip4_addr>>8)&0xff, (entry->val.ip4_addr>>16)&0xff, (entry->val.ip4_addr>>24)&0xff, entry->val.udp_port,
    entry->val.snp_available, entry->val.snp_enabled, is_new ? "(auto-detected!)" : "(detected!)" );
}

/* fd_snp_send sends a packet to a peer.

   Workflow:
   1. Validate input
   2. If proto==UDP, send packet as UDP
   3. Query connection by peer (meta)
   4. (likely case) If we have an established connection, send packet and return
   5. If we don't have a connection, create a new connection
   6. If packet_sz > 0, cache current packet
   7. If we did have a connection, return
   8. Prepare client_initial, overwrite packet
   9. Send client_initial */
int
fd_snp_send( fd_snp_t *    snp,
             uchar *       packet,
             ulong         packet_sz,
             fd_snp_meta_t meta ) {

  /* 1. Validate input */
  if( packet_sz > FD_SNP_MTU ) {
    return -1;
  }

  /* 2. If proto==UDP, send packet as UDP */
  ulong proto = meta & FD_SNP_META_PROTO_MASK;
  if( FD_LIKELY( proto==FD_SNP_META_PROTO_UDP ) ) {
    FD_SNP_LOG_TRACE( "[snp-send] UDP send" );
    /* metrics */
    ulong dest_meta_map_key = fd_snp_peer_addr_from_meta( meta );
    fd_snp_dest_meta_map_t sentinel = { 0 };
    fd_snp_dest_meta_map_t * dest_meta = fd_snp_dest_meta_map_query( snp->dest_meta_map, dest_meta_map_key, &sentinel );
    if( !!dest_meta->key && packet_sz>0UL ) {
      if( !!dest_meta->val.snp_enforced ) {
        /* This should never happen.  It would indicate an error. */
        snp->metrics_enf->tx_bytes_via_udp_cnt += packet_sz;
        snp->metrics_enf->tx_pkts_via_udp_cnt  += 1UL;
      }
      if( !!dest_meta->val.snp_available ) {
        snp->metrics_all->tx_bytes_via_udp_to_snp_avail_cnt += packet_sz;
        snp->metrics_all->tx_pkts_via_udp_to_snp_avail_cnt  += 1UL;
        if( !!dest_meta->val.snp_enforced ) {
          /* This should never happen.  It would indicate an error. */
          snp->metrics_enf->tx_bytes_via_udp_to_snp_avail_cnt += packet_sz;
          snp->metrics_enf->tx_pkts_via_udp_to_snp_avail_cnt  += 1UL;
        }
      }
    }
    return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta, NULL );
  }

  /* 3. Query connection by peer (meta) */
  ulong peer_addr = meta & FD_SNP_META_PEER_MASK;
  fd_snp_conn_t * conn = fd_snp_conn_query_by_peer( snp, peer_addr );

  /* 4. (likely case) If we have an established connection, send packet and return */
  if( FD_LIKELY( conn!=NULL && conn->state==FD_SNP_TYPE_HS_DONE ) ) {
    if( FD_UNLIKELY( conn->is_multicast ) ) {
      if( meta & FD_SNP_META_OPT_BROADCAST ) {
        return 0;
      }
      return fd_snp_finalize_multicast_and_invoke_tx_cb( snp, conn, packet, packet_sz, meta );
    }
    FD_SNP_LOG_TRACE( "[snp-send] SNP send %s", FD_SNP_LOG_CONN( conn ) );
    return fd_snp_finalize_snp_and_invoke_tx_cb( snp, conn, packet, packet_sz, meta, 0/*flow_tx_credit_bypass*/ );
  } /* else is implicit */

  /* 5. If we don't have a connection, create a new connection */
  if( conn==NULL ) {
    conn = fd_snp_conn_create( snp, peer_addr, /* is_server */ 0 );
    if( conn==NULL ) {
      return -1;
    }
    conn->is_server = 0;
  }
  if( FD_UNLIKELY( conn==NULL ) ) {
    FD_SNP_LOG_DEBUG_W( "[snp-send] fd_snp_conn_create returned NULL %s", FD_SNP_LOG_CONN( conn ) );
    return -1;
  }

  /* 6. If packet_sz > 0, cache current packet */
  if( packet_sz>0 ) {
    FD_SNP_LOG_TRACE( "[snp-send] cache packet" );
    if( FD_UNLIKELY( fd_snp_pkt_pool_store( snp, conn, packet, packet_sz, /* send */ 1 ) < 0 ) ) {
      FD_SNP_LOG_DEBUG_W( "unable to cache packet in pool due to insufficient space %s", fd_snp_log_conn( conn ) );
      return -1;
    }
  }

  /* 7. If we did have a connection, return */
  if( FD_UNLIKELY( conn->state != 0 ) ) {
    return 0; /* success */
  } /* else is implicit */

  /* 8. Prepare client_initial, overwrite packet */
  int sz = fd_snp_v1_client_init( &snp->config, conn, NULL, 0UL, packet + sizeof(fd_ip4_udp_hdrs_t), NULL );
  if( FD_UNLIKELY( sz<=0 ) ) {
    FD_SNP_LOG_DEBUG_W( "[snp-send] fd_snp_s0_client_initial failed %s", FD_SNP_LOG_CONN( conn ) );
    return -1;
  }

  /* 9. Send client_initial */
  FD_SNP_LOG_DEBUG_N( "[snp-send] SNP send hs1 %s", FD_SNP_LOG_CONN( conn ) );
  packet_sz = (ulong)sz + sizeof(fd_ip4_udp_hdrs_t);
  fd_snp_cache_packet_for_retry( conn, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE );
  return fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE, conn );
}

/* Workflow:
   1. Parse UDP: derive which app to send the packet to
   2. Parse SNP: derive proto and meta
   3. If proto==UDP, recv packet as UDP
   4. Query connection by session_id

   5. (likely case) Recv state machine

      R1. If multicast, accept
      R2. Validate conn, or drop
      R3. (likely case) conn established + validate integrity, accept
      R4. state==4, cache packet

   6. Handshake state machine
      ...

   7. Send handshake packet (if any)
   8. If connection is established, send/recv cached packets */
int
fd_snp_process_packet( fd_snp_t * snp,
                       uchar *    packet,
                       ulong      packet_sz ) {
  /* 1. Parse UDP: derive which app to send the packet to */
  if( packet_sz <= sizeof(fd_ip4_udp_hdrs_t) ) {
    return -1;
  }

  fd_ip4_udp_hdrs_t * hdr  = (fd_ip4_udp_hdrs_t *)packet;
  uint src_ip = hdr->ip4->saddr;
  ushort src_port = fd_ushort_bswap( hdr->udp->net_sport );
  ushort dst_port = fd_ushort_bswap( hdr->udp->net_dport );

  /* metrics */
  snp->metrics_all->rx_bytes_cnt += packet_sz;
  snp->metrics_all->rx_pkts_cnt  += 1UL;
  fd_snp_dest_meta_map_t sentinel = { 0 };
  fd_snp_dest_meta_map_t * dest_meta = fd_snp_dest_meta_map_query( snp->dest_meta_map,
    fd_snp_peer_addr_from_meta( fd_snp_meta_from_parts( 0, 0, src_ip, src_port ) ), &sentinel );
  int snp_enforced = dest_meta->key && dest_meta->val.snp_enforced;
  if( snp_enforced ) {
    snp->metrics_enf->rx_bytes_cnt += packet_sz;
    snp->metrics_enf->rx_pkts_cnt  += 1UL;
  }

  uchar snp_app_id;
  for( snp_app_id=0U; snp_app_id<snp->apps_cnt; snp_app_id++ ) {
    if( snp->apps[ snp_app_id ].port == dst_port ) {
      break;
    }
  }
  if( FD_UNLIKELY( snp_app_id>=snp->apps_cnt ) ) {
    /* The packet is not for SNP, ignore */
    FD_SNP_LOG_TRACE( "[snp-pkt] app not found for dst_port=%u, fallback to UDP", dst_port );
    fd_snp_meta_t meta = fd_snp_meta_from_parts( FD_SNP_META_PROTO_UDP, snp_app_id, src_ip, src_port );
    /* metrics */
    fd_snp_update_rx_metrics( snp, packet_sz, meta, NULL, dest_meta );
    return snp->cb.rx( snp->cb.ctx, packet, packet_sz, meta );
  }

  /* 2. Parse SNP: derive proto and meta */
  ulong proto = FD_SNP_META_PROTO_UDP;

  if( FD_LIKELY( packet_sz >= sizeof(fd_ip4_udp_hdrs_t) + 4 ) ) {
    uchar const * magic = packet + sizeof(fd_ip4_udp_hdrs_t);
    if( (*magic)=='S' && (*(magic+1))=='N' && (*(magic+2))=='P' ) {
      proto = FD_SNP_META_PROTO_V1;
    }
  }

  fd_snp_meta_t meta = fd_snp_meta_from_parts( proto, snp_app_id, src_ip, src_port );
  ulong peer_addr = meta & FD_SNP_META_PEER_MASK;

  /* 3. If proto==UDP, recv packet as UDP */
  if( proto==FD_SNP_META_PROTO_UDP ) {
    /* metrics */
    fd_snp_update_rx_metrics( snp, packet_sz, meta, NULL, dest_meta );
    return snp->cb.rx( snp->cb.ctx, packet, packet_sz, meta );
  } /* else is implicit */

  /* 4. Query connection by session_id */
  snp_hdr_t * head = (snp_hdr_t *)(packet + sizeof(fd_ip4_udp_hdrs_t));
  ulong session_id = head->session_id;
  fd_snp_conn_t * conn = fd_snp_conn_query( snp, session_id );

  /* metrics */
  fd_snp_update_rx_metrics( snp, packet_sz, meta, conn, dest_meta );

  /* 5. (likely case) Recv state machine */
  int type = snp_hdr_type( head );
  if( FD_LIKELY( type==FD_SNP_TYPE_PAYLOAD ) ) {
    /* R1. If multicast, accept */
    if( FD_UNLIKELY( fd_snp_ip_is_multicast( packet ) ) ) {
      return snp->cb.rx( snp->cb.ctx, packet, packet_sz, meta );
    }

    /* R2. Validate conn, or drop */
    if( FD_UNLIKELY( conn==NULL || conn->peer_addr != peer_addr ) ) {
      FD_SNP_LOG_DEBUG_W( "[snp-pkt] invalid conn or IP" );
      return -1;
    }

    /* R3. (likely case) conn established + validate integrity, accept */
    if( FD_LIKELY( conn->state==FD_SNP_TYPE_HS_DONE ) ) {
      return fd_snp_verify_snp_and_invoke_rx_cb( snp, conn, packet, packet_sz, meta );
    }

    /* R4. state==4 or 5, cache packet */
    if( FD_LIKELY( conn->state==FD_SNP_TYPE_HS_SERVER_FINI || conn->state==FD_SNP_TYPE_HS_CLIENT_FINI ) ) {
      if( FD_UNLIKELY( fd_snp_pkt_pool_store( snp, conn, packet, packet_sz, /* recv */ 0 ) < 0 ) ) {
        FD_SNP_LOG_DEBUG_W( "unable to cache packet in pool %s", fd_snp_log_conn( conn ) );
        return -1;
      };
      return 0;
    }

    return -1;
  }

  /* 6. Handshake state machine */

  uchar * pkt = packet + sizeof(fd_ip4_udp_hdrs_t);
  ulong pkt_sz = packet_sz - sizeof(fd_ip4_udp_hdrs_t);
  uchar to_sign[32];
  int sz = 0;
  fd_snp_conn_t conn_empty[1] = { 0 };
  conn_empty->peer_addr = peer_addr;
  conn_empty->snp_enforced = (uchar)snp_enforced; /* only used for accurate metrics */
  switch( type ) {

    /* HS1. Server receives client_init and sends server_init */
    case FD_SNP_TYPE_HS_CLIENT_INIT: {
      /* Whether there was or not an existing connection, we allow to create a new one */
      conn = conn_empty; /* As a side effect, conn is not NULL */
      sz = fd_snp_v1_server_init( &snp->config, conn, pkt, pkt_sz, pkt, NULL );
      FD_SNP_LOG_DEBUG_N( "[snp-hsk] fd_snp_v1_server_init sz=%d %s", sz, FD_SNP_LOG_CONN( conn ) );
    } break;

    /* HS2. Client receives server_init and sends client_cont */
    case FD_SNP_TYPE_HS_SERVER_INIT: {
      if( conn==NULL ) {
        return -1;
      }
      sz = fd_snp_v1_client_cont( &snp->config, conn, pkt, pkt_sz, pkt, NULL );
      FD_SNP_LOG_DEBUG_N( "[snp-hsk] fd_snp_v1_client_cont sz=%d %s", sz, FD_SNP_LOG_CONN( conn ) );
      if( sz > 0 ) {
        fd_snp_dest_meta_map_update_on_handshake( snp, conn );
      }
    } break;

    /* HS3. Server receives client_cont and sends server_fini */
    case FD_SNP_TYPE_HS_CLIENT_CONT: {
      sz = fd_snp_v1_server_fini_precheck( &snp->config, conn_empty, pkt, pkt_sz, pkt, to_sign );
      FD_SNP_LOG_DEBUG_N( "[snp-hsk] fd_snp_v1_server_fini_precheck sz=%d %s", sz, FD_SNP_LOG_CONN( conn_empty ) );
      if( FD_UNLIKELY( sz < 0 ) ) {
        return -1;
      }
      conn = fd_snp_conn_query_by_peer( snp, peer_addr );
      /* The likely case is that conn==NULL, ie. there's no existing conn to the peer,
         and the handshake proceeds as expected. */
      if( FD_LIKELY( conn==NULL || conn->state==FD_SNP_TYPE_HS_DONE ) ) {
        conn = fd_snp_conn_create( snp, peer_addr, /* is_server */ 1 );
      }
      if( conn==NULL ) {
        return -1;
      }
      if( conn->state==FD_SNP_TYPE_HS_SERVER_FINI ) {
        /* This immediate retry is not necessary, but it accelerates the handshake. */
        return fd_snp_retry_cached_packet( snp, conn );
      }
      sz = fd_snp_v1_server_fini( &snp->config, conn, pkt, pkt_sz, pkt, to_sign );
      FD_SNP_LOG_DEBUG_N( "[snp-hsk] fd_snp_v1_server_fini sz=%d %s", sz, FD_SNP_LOG_CONN( conn ) );
      if( FD_UNLIKELY( sz < 0 ) ) {
        return -1;
      }
      if( sz > 0 ) {
        fd_snp_dest_meta_map_update_on_handshake( snp, conn );
      }
      return fd_snp_cache_packet_and_invoke_sign_cb( snp, conn, packet, sz, to_sign );
    } break;

    /* HS4. Client receives server_fini and sends client_fini */
    case FD_SNP_TYPE_HS_SERVER_FINI: {
      if( conn==NULL ) {
        return -1;
      }
      if( FD_LIKELY( conn->state == FD_SNP_TYPE_HS_CLIENT_CONT ) ) {
        sz = fd_snp_v1_client_fini( &snp->config, conn, pkt, pkt_sz, pkt, to_sign );
        FD_SNP_LOG_DEBUG_N( "[snp-hsk] fd_snp_v1_client_fini sz=%d %s", sz, FD_SNP_LOG_CONN( conn ) );
        if( FD_UNLIKELY( sz < 0 ) ) {
          return -1;
        }
        conn->last_recv_ts = fd_snp_timestamp_ms();
        return fd_snp_cache_packet_and_invoke_sign_cb( snp, conn, packet, sz, to_sign );
      } else if( conn->state==FD_SNP_TYPE_HS_DONE ) {
        /* This immediate retry is necessary, because from the client perspective
           the handshake is completed, and thus housekeeping wouldn't be retrying.
           But if the server re-sends server_fini, it means it didn't receive
           client_fini, and so we have to retry. */
        conn->last_recv_ts = fd_snp_timestamp_ms();
        return fd_snp_retry_cached_packet( snp, conn );
      }
    } break;

    /* HS5. Server receives client_fini and accepts */
    case FD_SNP_TYPE_HS_CLIENT_FINI: {
      if( conn==NULL ) {
        return -1;
      }
      sz = fd_snp_v1_server_acpt( &snp->config, conn, pkt, pkt_sz, pkt, NULL );
      FD_SNP_LOG_DEBUG_N( "[snp-hsk] fd_snp_v1_server_acpt sz=%d %s", sz, FD_SNP_LOG_CONN( conn ) );
      if( FD_LIKELY( sz>=0 ) ) {
        conn->last_recv_ts = fd_snp_timestamp_ms();
        /* Update the default connection to peer_addr to this conn */
        fd_snp_conn_map_t sentinel = { 0 };
        fd_snp_conn_map_t * entry = fd_snp_conn_map_query( snp->conn_map, peer_addr, &sentinel );
        if( entry->val!=NULL && entry->val!=conn ) {
          entry->val = conn;
        }
        /* metrics */
        snp->metrics_all->conn_cur_established += 1UL;
        snp->metrics_all->conn_acc_established += 1UL;
        if( !!conn->snp_enforced ) {
          snp->metrics_enf->conn_cur_established += 1UL;
          snp->metrics_enf->conn_acc_established += 1UL;
        }
      }
    } break;

    /* Drop any other packet */
    default:
      return -1;
  }

  /* 7. Send handshake packet (if any) */
  if( FD_UNLIKELY( sz < 0 ) ) {
    return -1;
  }
  if( FD_LIKELY( sz > 0 ) ) {
    packet_sz = (ulong)sz + sizeof(fd_ip4_udp_hdrs_t);
    fd_snp_cache_packet_for_retry( conn, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE );
    sz = fd_snp_finalize_udp_and_invoke_tx_cb( snp, packet, packet_sz, meta | FD_SNP_META_OPT_HANDSHAKE, conn );
  }

  /* 8. If connection is established, send/recv cached packets */
  if( FD_UNLIKELY( conn && conn->state==FD_SNP_TYPE_HS_DONE ) ) {
    fd_snp_pkt_pool_process( snp, conn, meta );
  }

  return sz; /* return value is from the handshake msg, not cached packets */
}

int
fd_snp_process_signature( fd_snp_t *  snp,
                          ulong       session_id,
                          uchar const signature[ 64 ] ) {

  fd_snp_conn_t * conn = fd_snp_conn_query( snp, session_id );
  if( conn==NULL ) {
    return -1;
  }

  fd_snp_meta_t meta = conn->peer_addr | FD_SNP_META_PROTO_V1 | FD_SNP_META_OPT_BUFFERED | FD_SNP_META_OPT_HANDSHAKE;

  int sz;
  switch( conn->state ) {
    /* HS3. Server receives client_cont and sends server_fini */
    case FD_SNP_TYPE_HS_SERVER_FINI_SIG: {
      fd_snp_v1_server_fini_add_signature( conn, conn->last_pkt->data+sizeof(fd_ip4_udp_hdrs_t), signature );
      conn->retry_cnt = 0;
      conn->last_pkt->meta = meta;
      return fd_snp_finalize_udp_and_invoke_tx_cb( snp, conn->last_pkt->data, conn->last_pkt->data_sz, meta, conn );
    } break;

    /* HS4. Client receives server_fini and sends client_fini */
    case FD_SNP_TYPE_HS_CLIENT_FINI_SIG: {
      fd_snp_v1_client_fini_add_signature( conn, conn->last_pkt->data+sizeof(fd_ip4_udp_hdrs_t), signature );
      sz = fd_snp_finalize_udp_and_invoke_tx_cb( snp, conn->last_pkt->data, conn->last_pkt->data_sz, meta, conn );

      /* process cached packets before return */
      fd_snp_pkt_pool_process( snp, conn, meta );

      /* metrics */
      snp->metrics_all->conn_cur_established += 1UL;
      snp->metrics_all->conn_acc_established += 1UL;
      if( !!conn->snp_enforced ) {
        snp->metrics_enf->conn_cur_established += 1UL;
        snp->metrics_enf->conn_acc_established += 1UL;
      }

      return sz; /* return value is from the handshake msg, not cached packets */
    } break;
  }
  return -1;
}

void
fd_snp_housekeeping( fd_snp_t * snp ) {
  ulong max  = fd_snp_conn_pool_max( snp->conn_pool );
  ulong used = fd_snp_conn_pool_used( snp->conn_pool );
  ulong idx = 0;
  ulong used_ele = 0;
  fd_snp_conn_t * conn = snp->conn_pool;

#define FD_SNP_HANDSHAKE_RETRY_MAX (5U)
#define FD_SNP_HANDSHAKE_RETRY_MS  (500L)
#define FD_SNP_KEEP_ALIVE_MS       (4000L)
#define FD_SNP_TIMEOUT_MS          (FD_SNP_KEEP_ALIVE_MS * 3L + 1000L)
#define FD_SNP_DEST_META_UPDATE_MS (12000L)
#define FD_SNP_FLOW_RX_WMARK_MS    (4000L)

  long now = fd_snp_timestamp_ms();
  for( ; idx<max && used_ele<used; idx++, conn++ ) {
    if( conn->session_id == 0 ) continue;
    used_ele++;

    if( conn->state==FD_SNP_TYPE_INVALID ) {
      FD_SNP_LOG_DEBUG_W( "[snp-hkp] connection invalid %s", fd_snp_log_conn( conn ) );
      fd_snp_conn_delete( snp, conn );
      continue;
    }

    if( FD_SNP_TYPE_INVALID < conn->state && conn->state < FD_SNP_TYPE_HS_DONE ) {
      if( conn->retry_cnt >= FD_SNP_HANDSHAKE_RETRY_MAX ) {
        FD_SNP_LOG_DEBUG_W( "[snp-hkp] retry expired - deleting %s", FD_SNP_LOG_CONN( conn ) );
        /* metrics */
        snp->metrics_all->conn_acc_dropped_handshake   += 1UL;
        if( !!conn->snp_enforced ) {
          snp->metrics_enf->conn_acc_dropped_handshake += 1UL;
        }
        fd_snp_conn_delete( snp, conn );
        continue;
      }
      if( now > conn->last_sent_ts + FD_SNP_HANDSHAKE_RETRY_MS ) {
        FD_SNP_LOG_DEBUG_N( "[snp-hkp] retry %d %s", conn->retry_cnt, FD_SNP_LOG_CONN( conn ) );
        fd_snp_retry_cached_packet( snp, conn );
        conn->retry_cnt++;
        continue;
      }
    }

    if( FD_LIKELY( conn->state==FD_SNP_TYPE_HS_DONE ) ) {
      if( now > conn->last_recv_ts + FD_SNP_TIMEOUT_MS ) {
        FD_SNP_LOG_DEBUG_W( "[snp-hkp] timeout - deleting %s", FD_SNP_LOG_CONN( conn ) );
        /* metrics */
        snp->metrics_all->conn_acc_dropped_established   += 1UL;
        if( !!conn->snp_enforced ) {
          snp->metrics_enf->conn_acc_dropped_established += 1UL;
        }
        fd_snp_conn_delete( snp, conn );

        uint   ip4_addr = 0;
        ushort udp_port = 0;
        fd_snp_peer_addr_into_parts( &ip4_addr, &udp_port, conn->peer_addr );
        ulong dest_meta_map_key = fd_snp_dest_meta_map_key_from_conn( conn );
        fd_snp_dest_meta_map_t sentinel = { 0 };
        fd_snp_dest_meta_map_t * entry = fd_snp_dest_meta_map_query( snp->dest_meta_map, dest_meta_map_key, &sentinel );
        if( !entry->key ) {
          FD_SNP_LOG_DEBUG_W( "[snp-hkp] dest_meta_map unable to delete %s", FD_SNP_LOG_CONN( conn ) );
        } else {
          entry->val.snp_enabled = 0;
          FD_SNP_LOG_DEBUG_N( "[snp-hkp] %s snp_available %x snp_enabled %x (** disabled **)", FD_SNP_LOG_CONN( conn ), entry->val.snp_available, entry->val.snp_enabled );
          /* Try to re-establish the connection one more time. */
          fd_snp_meta_t meta = fd_snp_meta_from_parts( FD_SNP_META_PROTO_V1, 0/*app_id*/, ip4_addr, udp_port );
          uchar packet[ FD_SNP_MTU ] = { 0 };
          fd_snp_send( snp, packet, 0/*packet_sz*/, meta );
        }

        continue;
      }
      /* Flow rx watermark is updated when flow rx level nears the
         watermark by half the flow rx allocation.  This is arbitrary,
         and it tries to minimize credit starvation and the number of
         watermark updates.  Note that conn->flow_rx_alloc should be
         at least larger than the amount of bytes considered for the
         margin update and the bytes reserved beyond the next watermark
         (see below). */
      if( FD_UNLIKELY( ( conn->flow_rx_wmark  - conn->flow_rx_level ) < ( conn->flow_rx_alloc / 2 ) ) ) {
        /* The next watermark value must take into account any unused
           credits (in which case it references the the current level)
           and any overused credits (in which case it references the
           current watermark).  The receiver guarantees that there are
           FD_SNP_MTU bytes available beyond the next watermark, which
           may be crossed only once.  This minimizes the calculations
           around the crossing boundary and avoids weird edge cases. */
        long wmark = fd_long_min( conn->flow_rx_level, conn->flow_rx_wmark ) + conn->flow_rx_alloc - (long)FD_SNP_MTU;
        FD_SNP_LOG_TRACE( "[snp-hkp] updating flow rx wmark from %ld to %ld for %s level %ld", conn->flow_rx_wmark, wmark, FD_SNP_LOG_CONN( conn ), conn->flow_rx_level );
        conn->flow_rx_wmark = wmark;
        fd_snp_send_flow_rx_wmark_packet( snp, conn );
        continue;
      } else {
        if( FD_UNLIKELY( now > conn->flow_rx_wmark_tstamp + FD_SNP_FLOW_RX_WMARK_MS ) ) {
          FD_SNP_LOG_TRACE( "[snp-hkp] timed wmark update %ld level %ld at tstamp %016lx for %s", conn->flow_rx_wmark, conn->flow_rx_level, (ulong)conn->flow_rx_wmark_tstamp, FD_SNP_LOG_CONN( conn ) );
          fd_snp_send_flow_rx_wmark_packet( snp, conn );
          continue;
        }
      }
      if( now > conn->last_sent_ts + FD_SNP_KEEP_ALIVE_MS ) {
        FD_SNP_LOG_TRACE( "[snp-hkp] keep alive - pinging %s", FD_SNP_LOG_CONN( conn ) );
        fd_snp_send_ping( snp, conn );
        continue;
      }
    }
  }

  /* dest_meta_update and handshake retriggering. */
  if( now > snp->dest_meta_next_update_ts + FD_SNP_DEST_META_UPDATE_MS ) {
    ulong m_dest_meta_cnt_enf     = 0UL;
    ulong m_snp_available_cnt_all = 0UL;
    ulong m_snp_available_cnt_enf = 0UL;
    ulong m_snp_enabled_cnt_all   = 0UL;
    ulong m_snp_enabled_cnt_enf   = 0UL;
    fd_snp_dest_meta_map_t * curr_map = snp->dest_meta_map;
    fd_snp_dest_meta_map_t * next_map = curr_map==snp->dest_meta_map_a ? snp->dest_meta_map_b : snp->dest_meta_map_a;
    /* swap dest_meta_map and clone unexpired entries */
    snp->dest_meta_map = next_map;
    ulong slot_cnt = fd_snp_dest_meta_map_slot_cnt( curr_map );
    ulong key_cnt  = fd_snp_dest_meta_map_key_cnt( curr_map );
    ulong key_i    = 0UL;
    for( ulong i=0; i < slot_cnt && key_i < key_cnt; i++ ) {
      fd_snp_dest_meta_map_t * curr_entry = &curr_map[i];
      if( !fd_snp_dest_meta_map_key_equal( curr_entry->key, fd_snp_dest_meta_map_key_null() ) ) {
        /* clone current map's entry into next map's entry,
           excluding older ones.  Only use ==, since any
           other operation may required both to be ulong. */
        if( curr_entry->val.update_idx == snp->dest_meta_update_idx ) {
          /* update next_entry */
          fd_snp_dest_meta_map_t * next_entry = fd_snp_dest_meta_map_insert( next_map, curr_entry->key );
          next_entry->val = curr_entry->val;
          /* check if a handshake needs to be retriggered. */
          if( FD_UNLIKELY( ( !!next_entry->val.snp_available ) &&
                           (  !next_entry->val.snp_enabled   ) &&
                           ( now > next_entry->val.snp_handshake_tstamp + FD_SNP_DEST_META_UPDATE_MS ) ) ) {
            fd_snp_meta_t meta = fd_snp_meta_from_parts( FD_SNP_META_PROTO_V1, 0/*app_id*/, next_entry->val.ip4_addr, next_entry->val.udp_port );
            uchar packet[ FD_SNP_MTU ] = { 0 };
            FD_SNP_LOG_TRACE( "[snp-hsk] retry handshake at tstamp %016lx for %s", (ulong)next_entry->val.snp_handshake_tstamp, FD_SNP_LOG_CONN( conn ) );
            fd_snp_send( snp, packet, 0/*packet_sz*/, meta | FD_SNP_META_OPT_BUFFERED );
            /* randomly set the handshake timestamp, to prevent all entries from
               triggering at the same time in upcoming housekeeping(s).  The rng
               yields a ushort, in the range of [0, 65536) ms. */
            next_entry->val.snp_handshake_tstamp = now + (long)( fd_rng_ushort( snp->rng ) );
          }
          m_snp_available_cnt_all   += fd_ulong_if( !!next_entry->val.snp_available, 1UL, 0UL );
          m_snp_enabled_cnt_all     += fd_ulong_if( !!next_entry->val.snp_enabled,   1UL, 0UL );
          if( !!next_entry->val.snp_enforced ) {
            m_dest_meta_cnt_enf     += 1UL;
            m_snp_available_cnt_enf += fd_ulong_if( !!next_entry->val.snp_available, 1UL, 0UL );
            m_snp_enabled_cnt_enf   += fd_ulong_if( !!next_entry->val.snp_enabled,   1UL, 0UL );
          }
        }
        /* manually reset current map's entry, avoiding fd_snp_dest_meta_map_clear() overhead. */
        curr_entry->key = fd_snp_dest_meta_map_key_null();
        key_i += 1UL;
      }
    }
    /* manually reset current map's key_cnt, avoiding fd_snp_dest_meta_map_clear() overhead. */
    fd_snp_dest_meta_map_private_t * hdr = fd_snp_dest_meta_map_private_from_slot( curr_map );
    hdr->key_cnt = 0UL;
    /* prepare for the next update */
    snp->dest_meta_next_update_ts = now + FD_SNP_DEST_META_UPDATE_MS;

    /* metrics */
    snp->metrics_all->dest_meta_cnt               = fd_snp_dest_meta_map_key_cnt( snp->dest_meta_map );
    snp->metrics_all->dest_meta_snp_available_cnt = m_snp_available_cnt_all;
    snp->metrics_all->dest_meta_snp_enabled_cnt   = m_snp_enabled_cnt_all;

    snp->metrics_enf->dest_meta_cnt               = m_dest_meta_cnt_enf;
    snp->metrics_enf->dest_meta_snp_available_cnt = m_snp_available_cnt_enf;
    snp->metrics_enf->dest_meta_snp_enabled_cnt   = m_snp_enabled_cnt_enf;

    snp->metrics_all->conn_cur_total              = fd_snp_conn_pool_used( snp->conn_pool );
  }

#undef FD_SNP_HANDSHAKE_RETRY_MAX
#undef FD_SNP_HANDSHAKE_RETRY_MS
#undef FD_SNP_KEEP_ALIVE_MS
#undef FD_SNP_TIMEOUT_MS
#undef FD_SNP_DEST_META_UPDATE_MS
}

void
fd_snp_set_identity( fd_snp_t *    snp,
                     uchar const * new_identity ) {
  fd_memcpy( snp->config.identity, new_identity, 32UL );

  ulong max  = fd_snp_conn_pool_max( snp->conn_pool );
  ulong used = fd_snp_conn_pool_used( snp->conn_pool );
  ulong idx = 0;
  ulong used_ele = 0;
  fd_snp_conn_t * conn = snp->conn_pool;

  for( ; idx<max && used_ele<used; idx++, conn++ ) {
    if( conn->session_id == 0 ) continue;
    used_ele++;
    /* metrics */
    snp->metrics_all->conn_acc_dropped_set_identity += 1UL;
    if( !!conn->snp_enforced ) {
      snp->metrics_enf->conn_acc_dropped_set_identity += 1UL;
    }
    fd_snp_conn_delete( snp, conn );
  }
}
