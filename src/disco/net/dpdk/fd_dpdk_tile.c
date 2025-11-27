/* The dpdk tile translates Ethernet frames between DPDK PMDs and
   fd_tango. */

#include "../../metrics/fd_metrics.h"
#include "../../topo/fd_topo.h"

#include <rte_ethdev.h>

#define PKT_BURST_MAX (32UL)

#define MEMPOOL_CACHE_SIZE 256

/* fd_dpdk_tile_t is private tile state */

struct fd_dpdk_tile {
  ushort port_id;
  ushort queue_id;

  struct {
    ulong rx_pkt_cnt;
    ulong rx_bytes_total;
    ulong tx_pkt_cnt;
    ulong tx_bytes_total;
  } metrics;
};

typedef struct fd_dpdk_tile fd_dpdk_tile_t;

static ulong
scratch_align( void ) {
  return alignof(fd_dpdk_tile_t);
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_dpdk_tile_t), sizeof(fd_dpdk_tile_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_UNUSED static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  uint pool_depth = 4096UL;

  static struct rte_pktmbuf_extmem const ext_mem[1] = {{
    .buf_ptr  = umem,
    .buf_iova = RTE_BAD_IOVA, /* unused */
    .buf_len  = umem_sz,
    .elt_size = 2048UL
  }};

  struct rte_mempool * pool = rte_pktmbuf_pool_create_extbuf(
      /* name           */ "pkts",
      /* n              */ pool_depth,
      /* cache_size     */ MEMPOOL_CACHE_SIZE,
      /* priv_size      */ 0,
      /* data_room_size */ 2048UL,
      /* socket_id      */ (int)rte_socket_id(),
      /* ext_mem        */ ext_mem,
      /* ext_num        */ 1UL
  );
  if( FD_UNLIKELY( !pool ) ) FD_LOG_ERR(( "rte_pktmbuf_pool_create_extbuf failed" ));

  ushort port_id = 0;

  struct rte_eth_dev_info dev_info;
  int info_ret = rte_eth_dev_info_get( port_id, &dev_info );
  if( info_ret<0 ) FD_LOG_ERR(( "rte_eth_dev_info_get(port_id=%u) failed (%d)", port_id, info_ret ));

  struct rte_eth_conf eth_conf = {
    .txmode = {
      .mq_mode = RTE_ETH_MQ_TX_NONE
    }
  };
  int conf_ret = rte_eth_dev_configure( port_id, 1, 1, &eth_conf );
  if( conf_ret<0 ) FD_LOG_ERR(( "rte_eth_dev_configure failed (%d)", conf_ret ));

  int numa_id = rte_eth_dev_socket_id( port_id );

  ushort rx_desc_max = 2048;
  struct rte_eth_rxconf rx_conf = dev_info.default_rxconf;
  int rxq_setup_ret = rte_eth_rx_queue_setup( port_id, 0, rx_desc_max, (uint)numa_id, &rx_conf, pool );
  if( FD_UNLIKELY( rxq_setup_ret<0 ) ) FD_LOG_ERR(( "rte_eth_rx_queue_setup failed (%d)", rxq_setup_ret ));

  ushort tx_desc_max = 2048;
  struct rte_eth_txconf tx_conf = dev_info.default_txconf;
  int txq_setup_ret = rte_eth_tx_queue_setup( port_id, 0, tx_desc_max, (uint)numa_id, &tx_conf );
  if( FD_UNLIKELY( txq_setup_ret<0 ) ) FD_LOG_ERR(( "rte_eth_tx_queue_setup failed (%d)", txq_setup_ret ));

  int start_ret = rte_eth_dev_start( port_id );
  if( FD_UNLIKELY( start_ret<0 ) ) FD_LOG_ERR(( "rte_eth_dev_start failed (%d)", start_ret ));
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;
}

static void
during_housekeeping( fd_dpdk_tile_t * ctx ) {
  (void)ctx;
}

static void
metrics_write( fd_dpdk_tile_t * ctx ) {
  FD_MCNT_SET( DPDK, RX_PKT_CNT,     ctx->metrics.rx_pkt_cnt     );
  FD_MCNT_SET( DPDK, RX_BYTES_TOTAL, ctx->metrics.rx_bytes_total );
  FD_MCNT_SET( DPDK, TX_PKT_CNT,     ctx->metrics.tx_pkt_cnt     );
  FD_MCNT_SET( DPDK, TX_BYTES_TOTAL, ctx->metrics.tx_bytes_total );
}

/* rx_burst_fwd forwards a batch of newly received packets to downstream
   tiles.  Assumes that packet frames are available in shm and exposed
   to downstream tiles already.  Publishes fragment metadatas to
   descriptor rings (if possible), or returns frames back to
   rte_mempool. */

static void
rx_burst_fwd( fd_dpdk_tile_t *   ctx,
              struct rte_mbuf ** pkt,
              ulong              pkt_cnt ) {
  /* FIXME actually handle packets */
  ctx->metrics.rx_pkt_cnt += pkt_cnt;
  for( ulong i=0U; i<pkt_cnt; i++ ) {
    ctx->metrics.rx_bytes_total += pkt[ i ]->data_len;
    rte_pktmbuf_free( pkt[ i ] );
  }
}

/* after_credit is executed every run loop iteration.
   Checks for new RX packets and TX completions. */

static void
after_credit( fd_dpdk_tile_t *    ctx,
              fd_stem_context_t * stem,
              int *               poll_in,
              int *               charge_busy ) {
  (void)stem; (void)poll_in;

  struct rte_mbuf * rx_pkts[ PKT_BURST_MAX ];
  ulong rx_cnt = rte_eth_rx_burst( ctx->port_id, ctx->queue_id, rx_pkts, PKT_BURST_MAX );
  if( FD_LIKELY( rx_cnt ) ) {
    rx_burst_fwd( ctx, rx_pkts, rx_cnt );
    *charge_busy = 1;
  }
}

#define STEM_CALLBACK_CONTEXT_TYPE        fd_dpdk_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_dpdk_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_BURST                        1UL /* ignored */
#define STEM_LAZY                         130000UL /* 130us */
#include "../../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_dpdk = {
  .name              = "dpdk",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
