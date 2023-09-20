#include "fd_frank.h"
#include "../../tango/xdp/fd_xdp.h"
#include "../../tango/xdp/fd_xsk_private.h" /* FIXME: Needed to get the file descriptor for sandbox */
#include "../../tango/fd_tango.h"
#include "../../tango/ip/fd_ip.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../ballet/shred/fd_shredder.h"
#include "../../ballet/shred/fd_shred.h"

#include <stdio.h>
#include <linux/unistd.h>

#define FD_SHRED_TAG 0x5119317711eUL /* SHRED TILE */
#define MAX_SHRED_DESTS (1UL<<20) /* 1 million. Need to update the mvcc construction if this changes */

/* INTERNAL HELPER STRUCTS */
/* Part 1: Shreds */
/* The memory this tile uses is a bit complicated and full of logical
   aliasing to facilitate zero-copy use.  We have a dcache containing
   fd_shred_pkt34_t objects, which are basically 34 fd_shred_pkt_t
   objects, where 34 is set so that the size of the fd_shred_pkt34_t
   object is less than USHORT_MAX, which facilitates sending it using
   Tango.  Then, for each set of 4 consecutive fd_shred_pkt34_t objects,
   we have an fd_fec_set_t.  The first 34 data shreds point to the
   payload section of the payload section of each of the packets in the
   first fd_shred_pkt34_t.  The other 33 data shreds point into the
   second fd_shred_pkt34_t.  Similar for the parity shreds pointing into
   the third and fourth fd_shred_pkt34_t.  Additionally, for each set of
   4 consecutive fd_shred_pkt34_t objects, we have two arrays of
   fd_aio_pkt_info_t s, one for data shreds and one for parity shreds,
   with 67 elements in each.  These point to the first byte of the
   corresponding packet in the fd_shred_pkt34_t objects.  Again, the
   last fd_shred_pkt_t of the second and fourth fd_shred_pkt34_t object
   is never referenced. */

struct __attribute__((packed)) fd_shred_pkt {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];

  uchar payload[FD_SHRED_MAX_SZ];
};
typedef struct fd_shred_pkt fd_shred_pkt_t;

struct fd_shred_pkt_34 {
  ulong shred_cnt;
  ulong stride;
  ulong offset;
  ulong shred_sz; /* The size of each shred */
  /* For i in [0, shred_cnt), shred i's payload spans bytes
     [i*stride+offset, i*stride+offset+shred_sz ), counting from the
     start of the struct, not this point. */
  fd_shred_pkt_t pkts[ 34 ];
};
typedef struct fd_shred_pkt_34 fd_shred_pkt_34_t;

#define DCACHE_ENTRIES_PER_FEC_SET (4UL)
FD_STATIC_ASSERT( sizeof(fd_shred_pkt_34_t) < USHORT_MAX, shred_34 );
FD_STATIC_ASSERT( sizeof(fd_shred_pkt_34_t)==43216UL, shred_34 );
FD_STATIC_ASSERT( 34*DCACHE_ENTRIES_PER_FEC_SET >= FD_REEDSOL_DATA_SHREDS_MAX+FD_REEDSOL_PARITY_SHREDS_MAX, shred_34 );

struct fd_shred_fec_meta {
  fd_fec_set_t set[1];
  fd_aio_pkt_info_t d_pkt_info[ FD_REEDSOL_DATA_SHREDS_MAX   ];
  fd_aio_pkt_info_t p_pkt_info[ FD_REEDSOL_PARITY_SHREDS_MAX ];
};
typedef struct fd_shred_fec_meta fd_shred_fec_meta_t;



/* Part 2: Shred destinations */
struct __attribute__((packed)) fd_shred_dest2 {
  uchar  pubkey[32];
  ulong  stake_lamports;
  uint   ip4_addr; /* FIXME: Check that this is the host byte order */
  ushort udp_port;
};
typedef struct fd_shred_dest2 fd_shred_dest2_t;

struct fd_stake_weighted_shred_dest {
  fd_shred_dest2_t d;
  uchar  mac_addr[6]; /* The mac address is not included in what we get
                         from the mvcc, but we need it, and it makes the
                         struct packing better anyways. */
};
typedef struct fd_stake_weighted_shred_dest fd_shred_dest_t;


int
drop_aio_recv( void *                    ctx,
               fd_aio_pkt_info_t const * batch,
               ulong                     batch_cnt,
               ulong *                   opt_batch_idx,
               int                       flush ) {
  (void)opt_batch_idx;
  (void)ctx;
  (void)batch;
  (void)batch_cnt;
  (void)flush;

  return FD_AIO_SUCCESS;
}

static inline int
send_loop_helper( fd_aio_t const * tx_aio,
                  fd_aio_pkt_info_t const * data,
                  ulong cnt, int flush ) {
  ulong total_sent = 0UL;
  while( total_sent<cnt ) {
    ulong okay_cnt = 0UL;
    int send_rc = fd_aio_send( tx_aio, data+total_sent, cnt-total_sent, &okay_cnt, flush );
    if( FD_LIKELY( send_rc>=0 ) ) return send_rc;
    if( FD_UNLIKELY( send_rc!=FD_AIO_ERR_AGAIN ) ) return send_rc;
    flush = 1;
    total_sent += okay_cnt;
  }
  return 0;
}


static void
init( fd_frank_args_t * args ) {
  FD_LOG_INFO(( "loading %s", "xsk" ));
  args->xsk = fd_xsk_join( fd_wksp_pod_map( args->tile_pod, "xsk" ) );
  if( FD_UNLIKELY( !args->xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

  void * _ip = fd_wksp_alloc_laddr( fd_wksp_containing( args->tile_pod ), fd_ip_align(), fd_ip_footprint( 256UL, 256UL ), FD_SHRED_TAG );
  args->other = fd_ip_join( fd_ip_new( _ip, 256UL, 256UL ) );
  if( FD_UNLIKELY( !args->other ) ) FD_LOG_ERR(( "fd_ip_join failed" ));
}



static void
run( fd_frank_args_t * args ) {

  FD_LOG_INFO(( "joining cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  ulong * cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );
  if( FD_UNLIKELY( !cnc_diag ) ) FD_LOG_ERR(( "fd_cnc_app_laddr failed" ));
  cnc_diag[ FD_FRANK_CNC_DIAG_PID ] = (ulong)args->pid;
  ulong tile_idx = fd_tile_idx();


  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP    ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT   ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_HA_FILT_SZ  ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_CNT ] ) = 0UL;
  FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_SV_FILT_SZ  ] ) = 0UL;
  FD_COMPILER_MFENCE();


  /* Input IPC objects */
  FD_LOG_INFO(( "joining mcache%lu", args->tile_idx ));
  char path[ 32 ];
  snprintf( path, sizeof(path), "mcache%lu", args->tile_idx );
  fd_frag_meta_t * in_mcache = fd_mcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !in_mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   in_depth = fd_mcache_depth( in_mcache );
  ulong * in_sync  = fd_mcache_seq_laddr( in_mcache );
  ulong   in_seq   = fd_mcache_seq_query( in_sync );

  fd_frag_meta_t const * in_mline = in_mcache + fd_mcache_line_idx( in_seq, in_depth );

  FD_LOG_INFO(( "joining dcache%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "dcache%lu", args->tile_idx );
  uchar * in_dcache = fd_dcache_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !in_dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * wksp = fd_wksp_containing( in_dcache ); /* chunks are referenced relative to the containing workspace */
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));

  FD_LOG_INFO(( "joining fseq%lu", args->tile_idx ));
  snprintf( path, sizeof(path), "fseq%lu", args->tile_idx );
  ulong * in_fseq = fd_fseq_join( fd_wksp_pod_map( args->in_pod, path ) );
  if( FD_UNLIKELY( !in_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * in_fseq_diag = (ulong *)fd_fseq_app_laddr( in_fseq );
  if( FD_UNLIKELY( !in_fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] ) = 0UL;
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] ) = 0UL;
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_FILT_CNT  ] ) = 0UL;
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_FILT_SZ   ] ) = 0UL;
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] ) = 0UL;
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] ) = 0UL;
  FD_VOLATILE( in_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT  ] ) = 0UL; /* Managed by the fctl */
  FD_COMPILER_MFENCE();
  ulong accum_pub_cnt   = 0UL;
  ulong accum_pub_sz    = 0UL;
  ulong accum_ovrnp_cnt = 0UL;
  ulong accum_ovrnr_cnt = 0UL;


  /* Output IPC objects */
  FD_LOG_INFO(( "joining mcache" ));
  fd_frag_meta_t * out_mcache = fd_mcache_join( fd_wksp_pod_map( args->out_pod, "mcache" ) );
  if( FD_UNLIKELY( !out_mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong   out_depth = fd_mcache_depth    ( out_mcache );
  ulong * out_sync  = fd_mcache_seq_laddr( out_mcache );
  ulong   out_seq   = fd_mcache_seq_query( out_sync   );

  FD_LOG_INFO(( "joining dcache" ));
  uchar * out_dcache = fd_dcache_join( fd_wksp_pod_map( args->out_pod, "dcache" ) );
  if( FD_UNLIKELY( !out_dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));
  fd_wksp_t * out_wksp = fd_wksp_containing( out_dcache );
  if( FD_UNLIKELY( !out_wksp ) ) FD_LOG_ERR(( "fd_wksp_containing failed" ));
  ulong   chunk0 = fd_dcache_compact_chunk0( out_wksp, out_dcache );
  ulong   wmark  = fd_dcache_compact_wmark ( out_wksp, out_dcache, sizeof(fd_shred_pkt_34_t) );
  ulong   chunk  = chunk0;
  ulong out_buffer_fec_sets = out_depth / DCACHE_ENTRIES_PER_FEC_SET;

  FD_LOG_INFO(( "joining fseq" ));
  ulong * out_fseq = fd_fseq_join( fd_wksp_pod_map( args->out_pod, "fseq" ) );
  if( FD_UNLIKELY( !out_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  ulong * out_fseq_diag = (ulong *)fd_fseq_app_laddr( out_fseq );
  if( FD_UNLIKELY( !out_fseq_diag ) ) FD_LOG_ERR(( "fd_fseq_app_laddr failed" ));
  FD_VOLATILE( out_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ) = 0UL; /* Managed by the fctl */

  int   backp        = 1;
  ulong out_cr_avail = 0UL;

  /* One entry batch might result in up to 4 outgoing messages to the
     shredder tile. */
  const ulong out_burst = 4UL;

  /* Setup local objects used by this tile */

  fd_xsk_t * xsk = args->xsk;

  FD_LOG_INFO(( "joining xsk_aio" ));
  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_pod_map( args->tile_pod, "xsk_aio" ), xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));

  uchar  src_mac[6];
  ushort net_port;
  uint   net_ip4;

  if( 1 ) {
    const uchar * _mac  = fd_pod_query_buf   ( args->tile_pod, "src_mac",       NULL );
    uint          _ip4  = fd_pod_query_uint  ( args->tile_pod, "src_ip",          0U );
    ushort        _port = fd_pod_query_ushort( args->tile_pod, "src_port", (ushort)0 );

    if( FD_UNLIKELY( !_mac  ) ) FD_LOG_ERR(( "mac not found"  ));
    if( FD_UNLIKELY( !_ip4  ) ) FD_LOG_ERR(( "ip not found"   ));
    if( FD_UNLIKELY( !_port ) ) FD_LOG_ERR(( "port not found" ));

    FD_LOG_INFO(( "Transmitting from " FD_IP4_ADDR_FMT ":%hu ("FD_ETH_MAC_FMT")", FD_IP4_ADDR_FMT_ARGS( _ip4 ), _port, FD_ETH_MAC_FMT_ARGS( _mac ) ));

    net_ip4  = fd_uint_bswap  ( _ip4  );
    net_port = fd_ushort_bswap( _port );
    memcpy( src_mac, _mac, 6UL );
  }

  uchar shred_key[64];
  uchar * shred_public_key = shred_key+32UL;

  {
    /* TODO: Move this to a signing tile */
    ulong key_sz = 0UL;
    const uchar * _identity_key  = fd_pod_query_buf( args->tile_pod, "identity_key", &key_sz );
    if( FD_UNLIKELY( !_identity_key  ) ) FD_LOG_ERR(( "identity_key not found" ));
    if( FD_UNLIKELY( key_sz != 64UL ) ) FD_LOG_WARNING(( "identity_key %lu not 64 bytes", key_sz ));
    memcpy( shred_key, _identity_key, 64UL );
  }

  fd_mvcc_t * cluster_nodes_mvcc = fd_mvcc_join( fd_wksp_pod_map( args->tile_pod, "cluster_nodes" ) );
  if( FD_UNLIKELY( !cluster_nodes_mvcc ) ) FD_LOG_ERR(( "fd_mvcc_join failed" ));


  FD_LOG_INFO(( "configuring flow control" ));
  ulong cr_max    = fd_pod_query_ulong( args->tile_pod, "cr_max",    0UL );
  ulong cr_resume = fd_pod_query_ulong( args->tile_pod, "cr_resume", 0UL );
  ulong cr_refill = fd_pod_query_ulong( args->tile_pod, "cr_refill", 0UL );
  long  lazy      = fd_pod_query_long ( args->tile_pod, "lazy",      0L  );
  FD_LOG_INFO(( "cr_max    %lu", cr_max    ));
  FD_LOG_INFO(( "cr_resume %lu", cr_resume ));
  FD_LOG_INFO(( "cr_refill %lu", cr_refill ));
  FD_LOG_INFO(( "lazy      %li", lazy      ));

  fd_fctl_t * in_fctl = fd_fctl_cfg_done( fd_fctl_cfg_rx_add( fd_fctl_join( fd_fctl_new( fd_alloca( FD_FCTL_ALIGN,
                                                                                                 fd_fctl_footprint( 1UL ) ),
                                                                                      1UL ) ),
                                                           in_depth, in_fseq, &in_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
                                       1UL /*cr_burst*/, cr_max, cr_resume, cr_refill );
  if( FD_UNLIKELY( !in_fctl ) ) FD_LOG_ERR(( "Unable to create flow control" ));
  FD_LOG_INFO(( "using cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu",
                fd_fctl_cr_burst( in_fctl ), fd_fctl_cr_max( in_fctl ), fd_fctl_cr_resume( in_fctl ), fd_fctl_cr_refill( in_fctl ) ));


  fd_fctl_t * out_fctl = fd_fctl_cfg_done( fd_fctl_cfg_rx_add( fd_fctl_join( fd_fctl_new( fd_alloca( FD_FCTL_ALIGN,
                                                                                                     fd_fctl_footprint( 1UL ) ),
                                                                                          1UL ) ),
                                                              out_depth, out_fseq, &out_fseq_diag[ FD_FSEQ_DIAG_SLOW_CNT ] ),
                                          out_burst, cr_max, cr_resume, cr_refill );
  if( FD_UNLIKELY( !out_fctl ) ) FD_LOG_ERR(( "Unable to create flow control" ));
  FD_LOG_INFO(( "using out cr_burst %lu, cr_max %lu, cr_resume %lu, cr_refill %lu",
                fd_fctl_cr_burst( out_fctl ), fd_fctl_cr_max( out_fctl ), fd_fctl_cr_resume( out_fctl ), fd_fctl_cr_refill( out_fctl ) ));

  if( lazy<=0L ) lazy = fd_long_min( fd_tempo_lazy_default( in_depth ), fd_tempo_lazy_default( out_depth ) );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( args->tile_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (seed %u)", seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));


  /* This is a "send-only" tile at the moment.  Drop anything received. */
  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, xsk_aio, drop_aio_recv ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  fd_xsk_aio_set_rx( xsk_aio, aio );

  fd_aio_t const * tx_aio = fd_xsk_aio_get_tx( xsk_aio );

  /* Prepare the local objects */
  ulong shred_scratch_footprint = FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(
              FD_LAYOUT_INIT,
              FD_SHREDDER_ALIGN,            FD_SHREDDER_FOOTPRINT                             ),
              alignof(fd_shred_fec_meta_t), sizeof(fd_shred_fec_meta_t) * out_buffer_fec_sets ),
              alignof(fd_shred_dest_t),     sizeof(fd_shred_dest_t    ) * MAX_SHRED_DESTS     ),
              alignof(ulong),               sizeof(ulong              ) * MAX_SHRED_DESTS     ),
          128UL );


  void * shred_scratch = fd_wksp_alloc_laddr( fd_wksp_containing( args->tile_pod ), 128UL, shred_scratch_footprint, FD_SHRED_TAG );
  if( FD_UNLIKELY( !shred_scratch ) ) FD_LOG_ERR(( "allocating memory for shred scratch failed" ));

  FD_SCRATCH_ALLOC_INIT( sscratch, shred_scratch );
  void * _shredder                  = FD_SCRATCH_ALLOC_APPEND( sscratch, FD_SHREDDER_ALIGN,
                                          FD_SHREDDER_FOOTPRINT );
  fd_shred_fec_meta_t * set_meta    = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(fd_shred_fec_meta_t),
                                                                         sizeof (fd_shred_fec_meta_t) * out_buffer_fec_sets   );
  fd_shred_dest_t * shred_dest      = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(fd_shred_dest_t    ),
                                                                         sizeof (fd_shred_dest_t    ) * MAX_SHRED_DESTS       );
  ulong * stake_weight              = FD_SCRATCH_ALLOC_APPEND( sscratch, alignof(ulong),
                                                                         sizeof (ulong              ) * MAX_SHRED_DESTS       );
  FD_SCRATCH_ALLOC_FINI( sscratch, 128UL );


  ushort shred_version = (ushort)0; // FIXME
  fd_shredder_t * shredder = fd_shredder_join( fd_shredder_new( _shredder, shred_public_key, shred_version ) );

  fd_shred_dest_t null_dest[1] = { 0 };

  ulong prev_contact_version = 0UL;
  ulong shred_dest_cnt       = 0UL;

  FD_LOG_NOTICE(( "Transmitting on interface %s queue %d", fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));

  ulong prep_chunk = chunk0;
  ulong fec_stride_chunk = 0UL;
  /* Prepare Ethernet, IP, UDP headers for all packets */
  for( ulong i=0UL; i<out_buffer_fec_sets; i++ ) {
    fd_shred_fec_meta_t * m = set_meta+i;

    fd_shred_pkt_34_t * p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, prep_chunk );
    p34->stride   = (ulong)p34->pkts[1].payload - (ulong)p34->pkts[0].payload;
    p34->offset   = (ulong)p34->pkts[0].payload - (ulong)p34;
    p34->shred_sz = 1203UL;

    for( ulong j=0UL; j<FD_REEDSOL_DATA_SHREDS_MAX;   j++ ) {
      fd_shred_pkt_t * pkt = p34->pkts + (j%34UL);
      m->set->data_shreds[   j ] = pkt->payload;
      m->d_pkt_info[ j ].buf = pkt;
      m->d_pkt_info[ j ].buf_sz = 1203UL + sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

      fd_memset( pkt->eth->dst, 0,       6UL );
      fd_memcpy( pkt->eth->src, src_mac, 6UL );
      pkt->eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

      pkt->ip4->ihl       = 5U;
      pkt->ip4->version   = 4U;
      pkt->ip4->tos       = (uchar)0;
      pkt->ip4->net_tot_len = fd_ushort_bswap( 1203UL + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );
      pkt->ip4->net_frag_off  = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
      pkt->ip4->ttl       = (uchar)64;
      pkt->ip4->protocol  = FD_IP4_HDR_PROTOCOL_UDP;
      pkt->ip4->check     = 0U;
      pkt->ip4->saddr     = net_ip4;
      pkt->ip4->daddr     = 0U; /* varies by shred */

      pkt->udp->net_sport = net_port;
      pkt->udp->net_dport = (ushort)0; /* varies by shred */
      pkt->udp->net_len   = fd_ushort_bswap( (ushort)(1203UL + sizeof(fd_udp_hdr_t)) );
      pkt->udp->check     = (ushort)0;

      if( j==33UL ) {
        prep_chunk = fd_dcache_compact_next( prep_chunk, sizeof(fd_shred_pkt_34_t), chunk0, wmark );
        FD_TEST( prep_chunk != chunk0 );
        p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, prep_chunk );
        p34->stride   = (ulong)p34->pkts[1].payload - (ulong)p34->pkts[0].payload;
        p34->offset   = (ulong)p34->pkts[0].payload - (ulong)p34;
        p34->shred_sz = 1203UL;
      }
    }

    prep_chunk = fd_dcache_compact_next( prep_chunk, sizeof(fd_shred_pkt_34_t), chunk0, wmark );
    FD_TEST( prep_chunk != chunk0 );
    p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, prep_chunk );
    p34->stride   = (ulong)p34->pkts[1].payload - (ulong)p34->pkts[0].payload;
    p34->offset   = (ulong)p34->pkts[0].payload - (ulong)p34;
    p34->shred_sz = 1228UL;

    for( ulong j=0UL; j<FD_REEDSOL_PARITY_SHREDS_MAX; j++ ) {
      fd_shred_pkt_t * pkt = p34->pkts + (j%34UL);
      m->set->parity_shreds[   j ] = pkt->payload;
      m->p_pkt_info[ j ].buf = pkt;
      m->p_pkt_info[ j ].buf_sz = 1228UL + sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);

      fd_memset( pkt->eth->dst, 0,       6UL );
      fd_memcpy( pkt->eth->src, src_mac, 6UL );
      pkt->eth->net_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );

      pkt->ip4->ihl       = 5U;
      pkt->ip4->version   = 4U;
      pkt->ip4->tos       = (uchar)0;
      pkt->ip4->net_tot_len = fd_ushort_bswap( 1228UL + sizeof(fd_ip4_hdr_t)+sizeof(fd_udp_hdr_t) );
      pkt->ip4->net_frag_off  = fd_ushort_bswap( FD_IP4_HDR_FRAG_OFF_DF );
      pkt->ip4->ttl       = (uchar)64;
      pkt->ip4->protocol  = FD_IP4_HDR_PROTOCOL_UDP;
      pkt->ip4->check     = 0U;
      pkt->ip4->saddr     = net_ip4;
      pkt->ip4->daddr     = 0U; /* varies by shred */

      pkt->udp->net_sport = net_port;
      pkt->udp->net_dport = (ushort)0; /* varies by shred */
      pkt->udp->net_len   = fd_ushort_bswap( (ushort)(1228UL + sizeof(fd_udp_hdr_t)) );
      pkt->udp->check     = (ushort)0;

      if( j==33UL ) {
        prep_chunk = fd_dcache_compact_next( prep_chunk, sizeof(fd_shred_pkt_34_t), chunk0, wmark );
        FD_TEST( prep_chunk != chunk0 );
        p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, prep_chunk );
        p34->stride   = (ulong)p34->pkts[1].payload - (ulong)p34->pkts[0].payload;
        p34->offset   = (ulong)p34->pkts[0].payload - (ulong)p34;
        p34->shred_sz = 1228UL;
      }
    }

    prep_chunk = fd_dcache_compact_next( prep_chunk, sizeof(fd_shred_pkt_34_t), chunk0, wmark );
    if( FD_UNLIKELY( i<out_buffer_fec_sets-1UL ) ) FD_TEST( prep_chunk != chunk0 );
    fec_stride_chunk = fd_ulong_if( i==0UL, prep_chunk-chunk0, fec_stride_chunk );
  }
  FD_TEST( prep_chunk == chunk0 );
  FD_TEST( chunk0 + out_buffer_fec_sets*fec_stride_chunk <= wmark + fec_stride_chunk/DCACHE_ENTRIES_PER_FEC_SET );

  fd_ip_t * ip = (fd_ip_t *)args->other;

  FD_LOG_NOTICE(( "Trying to find route to 1.1.1.1 to warmup the arp cache" ));
  while( 1 ) {
    uchar mac[6];
    uint  out_next_ip[1];
    uint  out_ifindex[1];

    fd_ip_route_fetch( ip );
    fd_ip_arp_fetch  ( ip );
    int res = fd_ip_route_ip_addr( mac, out_next_ip, out_ifindex, ip, 0x01010101 );
    if( res==FD_IP_NO_ROUTE  ) FD_LOG_ERR(( "Routing is misconfigured" ));
    if( res==FD_IP_SUCCESS   ) break;
    if( res!=FD_IP_PROBE_RQD ) FD_LOG_ERR(( "Unicast address resolved to multicast/broadcast" ));

    fd_ip_arp_t arp_packet[1];
    res = fd_ip_arp_gen_arp_probe( (uchar*)arp_packet, sizeof(fd_ip_arp_t), *out_next_ip, src_mac );
    if( res!=FD_IP_SUCCESS ) FD_LOG_ERR(( "Generation of arp probe failed" ));


    fd_aio_pkt_info_t arp_pkt_info[1] = {{ .buf = arp_packet, .buf_sz = sizeof(fd_ip_arp_t) }};
    int send_rc = send_loop_helper( tx_aio, arp_pkt_info, 1UL, 1 );
    if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO err sending warmup arp. Error: %s", fd_aio_strerror( send_rc ) ));
    FD_SPIN_PAUSE();
  }
  FD_LOG_NOTICE(( "ARP cache warmed" ));

  long now  = fd_tickcount();
  long then = now;

  ushort net_id = (ushort)0;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeep at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      FD_COMPILER_MFENCE();
      in_fseq_diag[ FD_FSEQ_DIAG_PUB_CNT   ] += accum_pub_cnt;
      in_fseq_diag[ FD_FSEQ_DIAG_PUB_SZ    ] += accum_pub_sz;
      in_fseq_diag[ FD_FSEQ_DIAG_OVRNP_CNT ] += accum_ovrnp_cnt;
      in_fseq_diag[ FD_FSEQ_DIAG_OVRNR_CNT ] += accum_ovrnr_cnt;
      FD_COMPILER_MFENCE();
      accum_pub_cnt   = 0UL;
      accum_pub_sz    = 0UL;
      accum_ovrnp_cnt = 0UL;
      accum_ovrnr_cnt = 0UL;

      FD_VOLATILE( in_fseq[0] ) = in_seq;

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Receive flow control credits */
      out_cr_avail = fd_fctl_tx_cr_update( out_fctl, out_cr_avail, out_seq );
      if( FD_UNLIKELY( backp ) ) {
        if( FD_LIKELY( out_cr_avail>=out_burst ) ) {
          FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP ] ) = 0UL;
          backp = 0;
        }
      }

      /* Reload stake contact info if it has changed */
      /* FIXME: Be careful when we do this to make sure we don't get
         data for the wrong epoch. */
      ulong version_a = fd_mvcc_version_query( cluster_nodes_mvcc );
      if( FD_LIKELY( !(version_a % 2) & (prev_contact_version != version_a) ) ) {
        FD_LOG_NOTICE(( "reloading contact info" ));
        int cluster_nodes_updated = 1;
        for(;;) {
          version_a = fd_mvcc_version_query( cluster_nodes_mvcc );
          if( FD_UNLIKELY( version_a % 2 ) ) {
            /* writer started writing. Bail and try again later */
            cluster_nodes_updated = 0;
            break;
          }

          uchar const * mvcc_app = fd_mvcc_app_laddr_const( cluster_nodes_mvcc );
          ulong dest_cnt     = ((ulong const *)fd_type_pun_const( mvcc_app ))[0];
          ulong total_weight = ((ulong const *)fd_type_pun_const( mvcc_app ))[1];
          /* TODO: Handle overflow case by making an entry with
             remaining weight at the end */
          (void)total_weight;

          FD_TEST( dest_cnt < MAX_SHRED_DESTS );

          fd_shred_dest2_t const * in_dests = fd_type_pun_const( mvcc_app + 2UL*sizeof(ulong) );
          shred_dest_cnt = 0UL;

          for( ulong i=0UL; i<dest_cnt; i++ ) {
            /* Resolve the destination */
            int can_send_to_dest = 0;
            if( FD_LIKELY( in_dests[i].ip4_addr ) ) {

              uint out_next_ip[1];
              uint out_ifindex[1];
              int res = fd_ip_route_ip_addr( shred_dest[shred_dest_cnt].mac_addr, out_next_ip, out_ifindex, ip, in_dests[i].ip4_addr );

              if( FD_LIKELY( res==FD_IP_SUCCESS ) ) {
                can_send_to_dest = 1;
                shred_dest[shred_dest_cnt].d = in_dests[i];
              }
              else if( FD_LIKELY( res==FD_IP_PROBE_RQD ) ) {
                fd_ip_arp_t arp_packet[1];
                res = fd_ip_arp_gen_arp_probe( (uchar*)arp_packet, sizeof(fd_ip_arp_t), *out_next_ip, src_mac );
                if( res!=FD_IP_SUCCESS ) FD_LOG_ERR(( "Generation of arp probe failed" ));


                fd_aio_pkt_info_t arp_pkt_info[1] = {{ .buf = arp_packet, .buf_sz = sizeof(fd_ip_arp_t) }};
                int send_rc = send_loop_helper( tx_aio, arp_pkt_info, 1UL, 1 );
                if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO err sending arp. Error: %s", fd_aio_strerror( send_rc ) ));
              } else {
                /* increment counter */
              }
            }
            if( FD_UNLIKELY( !can_send_to_dest ) ) {
              shred_dest[shred_dest_cnt].d.ip4_addr =         0U;
              shred_dest[shred_dest_cnt].d.udp_port = (ushort)0 ;
              memset( shred_dest[shred_dest_cnt].mac_addr, 0, 6UL );
            }

            stake_weight[shred_dest_cnt] = in_dests[i].stake_lamports;
            if( FD_LIKELY( !memcmp( in_dests[i].pubkey, shred_public_key, 32UL ) ) ) shred_dest_cnt++;
          }

          ulong version_b = fd_mvcc_version_query( cluster_nodes_mvcc );
          if( FD_LIKELY( version_a == version_b ) ) {
            /* read completed cleanly */
            fd_shredder_set_stake_weights( shredder, stake_weight, shred_dest_cnt );
            break;
          }
        }
        prev_contact_version = fd_ulong_if( cluster_nodes_updated, version_a, prev_contact_version );
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* If we're backpressured, then it doesn't make sense to try to read
       a new entry batch because we won't be able to do anything with
       it. */
    if( FD_UNLIKELY( out_cr_avail<out_burst ) ) {
      if( FD_UNLIKELY( !backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_IN_BACKP  ] ) = 1UL;
        FD_VOLATILE( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_FRANK_CNC_DIAG_BACKP_CNT ] )+1UL;
        backp = 1;
      }
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }


    /* See if there are any entry batches to shred */
    ulong seq_found = fd_frag_meta_seq_query( in_mline );
    long  diff      = fd_seq_diff( seq_found, in_seq );
    if( FD_UNLIKELY( diff ) ) { /* caught up or overrun, optimize for expected sequence number ready */
      if( FD_LIKELY( diff<0L ) ) { /* caught up */
        FD_SPIN_PAUSE();
        now = fd_tickcount();
        continue;
      }
      /* overrun ... recover */
      accum_ovrnp_cnt++;
      in_seq = seq_found;
      /* can keep processing from the new seq */
    }

    now = fd_tickcount();

    ulong         sz           = in_mline->sz;
    /*
    uchar const                 * dcache_entry     = fd_chunk_to_laddr_const( wksp, in_mline->chunk );
    fd_entry_batch_meta_t const * entry_batch_meta = (fd_entry_batch_meta_t const *)dcache_entry;
    uchar const *                 entry_batch      = dcache_entry + sizeof(fd_entry_batch_meta_t);
    ulong                         entry_batch_sz   = sz           - sizeof(fd_entry_batch_meta_t);
    */
    /* HACK: Restore the above commented code when batching works
       properly. */
    uchar * dcache_entry = fd_chunk_to_laddr( wksp, in_mline->chunk );
    fd_entry_batch_meta_t  entry_batch_meta[1] = { *(fd_entry_batch_meta_t const *)dcache_entry };
    uchar const *                 entry_batch      = dcache_entry + sizeof(fd_entry_batch_meta_t) - 8UL;
    ulong                         entry_batch_sz   = sz           - sizeof(fd_entry_batch_meta_t) + 8UL;
    /* Overwrite tick field with a 1 for the batch count */
    *(ulong *)entry_batch = 1UL;

    ulong fec_sets = fd_shredder_count_fec_sets( entry_batch_sz );
    FD_LOG_NOTICE(( "Shred tile got an entry batch of size %lu -> %lu -> %lu fec_sets. slot is %lu", sz, entry_batch_sz, fec_sets, entry_batch_meta->slot ));
    fd_shredder_init_batch( shredder, entry_batch, entry_batch_sz, entry_batch_meta );

    for( ulong i=0UL; i<fec_sets; i++ ) {

      /* Make a fec set */
      ulong set_idx = (chunk-chunk0) / fec_stride_chunk;
      fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, shred_key, set_meta[set_idx].set );

      fd_shred_pkt_34_t * p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, chunk );
      fd_aio_pkt_info_t send_pkts[ FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX ];
      ulong send_cnt = 0UL;

      for( ulong j=0UL; j<set->data_shred_cnt;   j++ ) {
        ulong dest_idx = set->data_shreds_dest_idx[ j ];
        fd_shred_dest_t * dest = fd_ptr_if( dest_idx!=FD_WSAMPLE_EMPTY, shred_dest+dest_idx, null_dest );

        if( FD_LIKELY( dest->d.ip4_addr ) ) {
          fd_shred_pkt_t * pkt = p34->pkts + (j%34UL);

          fd_memcpy( pkt->eth->dst, dest->mac_addr, 6UL );

          pkt->ip4->daddr      = fd_uint_bswap( dest->d.ip4_addr );
          pkt->ip4->net_id     = fd_ushort_bswap( net_id++ );
          pkt->ip4->check      = 0U;
          pkt->ip4->check      = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( pkt->ip4 ) );

          pkt->udp->net_dport  = fd_ushort_bswap( dest->d.udp_port );

          send_pkts[send_cnt++] = set_meta[set_idx].d_pkt_info[j];
        }

        if( j==33UL ) p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, chunk + 1UL*fec_stride_chunk/4UL );
      }

      p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, chunk + 2UL*fec_stride_chunk/4UL );

      for( ulong j=0UL; j<set->parity_shred_cnt; j++ ) {
        ulong dest_idx = set->parity_shreds_dest_idx[ j ];
        fd_shred_dest_t * dest = fd_ptr_if( dest_idx!=FD_WSAMPLE_EMPTY, shred_dest+dest_idx, null_dest );

        if( FD_LIKELY( dest->d.ip4_addr ) ) {
          fd_shred_pkt_t * pkt = p34->pkts + (j%34UL);

          fd_memcpy( pkt->eth->dst, dest->mac_addr, 6UL );

          pkt->ip4->daddr      = fd_uint_bswap( dest->d.ip4_addr );
          pkt->ip4->net_id     = fd_ushort_bswap( net_id++ );
          pkt->ip4->check      = 0U;
          pkt->ip4->check      = fd_ip4_hdr_check( ( fd_ip4_hdr_t const *) FD_ADDRESS_OF_PACKED_MEMBER( pkt->ip4 ) );

          pkt->udp->net_dport  = fd_ushort_bswap( dest->d.udp_port );

          send_pkts[send_cnt++] = set_meta[set_idx].p_pkt_info[j];
        }

        if( j==33UL ) p34 = (fd_shred_pkt_34_t *)fd_chunk_to_laddr_const( out_wksp, chunk + 3UL*fec_stride_chunk/4UL );
      }
      FD_LOG_NOTICE(( "FEC set had %lu + %lu packets. Sending %lu", set->data_shred_cnt, set->parity_shred_cnt, send_cnt ));

      /* Check to make sure we haven't been overrun.  We can't un-send
         the packets we've already sent on the network, but it doesn't
         make sense to buffer all these packets and then send them
         because skipping an entry batch is just as bad as sending a
         truncated entry batch.  Thus, we need to make sure backpressure
         is working here.  It is better to truncate an entry batch than
         to send a partially corrupt one though. */
      seq_found = fd_frag_meta_seq_query( in_mline );
      if( FD_UNLIKELY( fd_seq_ne( seq_found, in_seq ) ) ) {
        accum_ovrnr_cnt++;
        in_seq = seq_found;
        break;
      }

      accum_pub_cnt += set->data_shred_cnt;    accum_pub_sz += 1245UL * set->data_shred_cnt;
      accum_pub_cnt += set->parity_shred_cnt;  accum_pub_sz += 1270UL * set->parity_shred_cnt;

      int send_rc = send_loop_helper( tx_aio, send_pkts, send_cnt, 1 );
      if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO err sending shreds. Error: %s", fd_aio_strerror( send_rc ) ));


      ((fd_shred_pkt_34_t *)fd_chunk_to_laddr( out_wksp, chunk + 0UL*fec_stride_chunk/4UL ))->shred_cnt =
                                                                                fd_ulong_min( set->data_shred_cnt,   34UL );
      ((fd_shred_pkt_34_t *)fd_chunk_to_laddr( out_wksp, chunk + 1UL*fec_stride_chunk/4UL ))->shred_cnt =
                                                        set->data_shred_cnt   - fd_ulong_min( set->data_shred_cnt,   34UL );
      ((fd_shred_pkt_34_t *)fd_chunk_to_laddr( out_wksp, chunk + 2UL*fec_stride_chunk/4UL ))->shred_cnt =
                                                                                fd_ulong_min( set->parity_shred_cnt, 34UL );
      ((fd_shred_pkt_34_t *)fd_chunk_to_laddr( out_wksp, chunk + 3UL*fec_stride_chunk/4UL ))->shred_cnt =
                                                        set->parity_shred_cnt - fd_ulong_min( set->parity_shred_cnt, 34UL );

      ulong tsorig = fd_frag_meta_ts_comp( now );
      now = fd_tickcount();
      ulong tspub = fd_frag_meta_ts_comp( now );
      ulong   ctl = fd_frag_meta_ctl( tile_idx, 1, 1, 0 );
      ulong signature = 0UL; // TODO

      ulong debug_chunk = chunk;

      for( ulong k=0UL; k<DCACHE_ENTRIES_PER_FEC_SET; k++ ) {
        FD_TEST( chunk==debug_chunk + k*fec_stride_chunk/4UL );
        fd_mcache_publish( out_mcache, out_depth, out_seq, signature++, chunk, sizeof(fd_shred_pkt_34_t), ctl, tsorig, tspub );
        chunk = fd_dcache_compact_next( chunk, sizeof(fd_shred_pkt_34_t), chunk0, wmark );
        out_seq   = fd_seq_inc( out_seq, 1UL );
        FD_TEST( out_cr_avail>0UL );
        out_cr_avail--;
      }


      fd_xsk_aio_service( xsk_aio );
    }
    fd_shredder_fini_batch( shredder );

    fd_xsk_aio_service( xsk_aio );
    in_seq   = fd_seq_inc( in_seq, 1UL );
    in_mline = in_mcache + fd_mcache_line_idx( in_seq, in_depth );

    FD_LOG_NOTICE(( "Done with entry batch" ));
  }
}


static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_sendto,    /* fd_xsk requires sendto */
  __NR_recvfrom,  /* fd_io requires send and recv for ARP */
};

static ulong
allow_fds( fd_frank_args_t * args,
           ulong out_fds_sz,
           int * out_fds ) {
  (void)args;
  if( FD_UNLIKELY( out_fds_sz < 4 ) ) FD_LOG_ERR(( "out_fds_sz %lu", out_fds_sz ));
  out_fds[ 0 ] = 2; /* stderr */
  out_fds[ 1 ] = 3; /* logfile */
  out_fds[ 2 ] = args->xsk->xsk_fd;
  out_fds[ 3 ] = fd_ip_netlink_get( (fd_ip_t*)args->other )->fd;
  return 4UL;
}

fd_frank_task_t frank_shred = {
  .name              = "shred",
  .in_wksp           = "bank_shred",
  .out_wksp          = "shred_store",
  .extra_wksp        = NULL,
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls    = allow_syscalls,
  .allow_fds         = allow_fds,
  .init              = init,
  .run               = run,
};
