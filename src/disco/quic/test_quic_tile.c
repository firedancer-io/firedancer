/* test_quic_tile.c implements end-to-end QUIC tile tests.
   It ensures that basic TPU server functionality via UDP and QUIC  */

#include "../topo/fd_topo.h"
#include "../metrics/fd_metrics.h"
#include "../../waltz/quic/fd_quic.h"

#include <setjmp.h>

extern fd_topo_run_tile_t fd_tile_quic;

/* Tile shared memory */

static fd_topo_t topo[1];

#define LINK_IN_CNT  (1UL)
#define LINK_OUT_CNT (2UL)

#define LINK_NET_QUIC_DEPTH   (128UL)
#define LINK_NET_QUIC_MTU    (1500UL)
static __attribute__((aligned(FD_MCACHE_ALIGN))) uchar net_quic_mcache_mem[ FD_MCACHE_FOOTPRINT( LINK_NET_QUIC_DEPTH, 0UL ) ];

#define LINK_NET_QUIC_DATA_SZ (FD_DCACHE_REQ_DATA_SZ( LINK_NET_QUIC_MTU, LINK_NET_QUIC_DEPTH, 1UL, 1 ))
static __attribute__((aligned(FD_DCACHE_ALIGN))) uchar net_quic_dcache_mem[ FD_DCACHE_FOOTPRINT( LINK_NET_QUIC_DATA_SZ, 0UL ) ];

#define LINK_QUIC_TXN_DEPTH  (128UL)
#define LINK_QUIC_TXN_APP_SZ   (0UL)
static __attribute__((aligned(FD_MCACHE_ALIGN))) uchar quic_txn_mcache_mem[ FD_MCACHE_FOOTPRINT( LINK_QUIC_TXN_DEPTH, LINK_QUIC_TXN_APP_SZ ) ];

#define REASM_CNT          (256UL)
#define REASM_FOOTPRINT (505536UL)
static __attribute__((aligned(FD_TPU_REASM_ALIGN))) uchar reasm_mem[ REASM_FOOTPRINT ];

#define LINK_QUIC_NET_DEPTH  (128UL)
#define LINK_QUIC_NET_APP_SZ   (0UL)
static __attribute__((aligned(FD_MCACHE_ALIGN))) uchar quic_net_mcache_mem[ FD_MCACHE_FOOTPRINT( LINK_QUIC_NET_DEPTH, LINK_QUIC_NET_APP_SZ ) ];

#define LINK_QUIC_NET_DATA_SZ (FD_DCACHE_REQ_DATA_SZ( LINK_NET_QUIC_MTU, LINK_QUIC_NET_DEPTH, 1UL, 1 ))
static __attribute__((aligned(FD_DCACHE_ALIGN))) uchar quic_net_dcache_mem[ FD_DCACHE_FOOTPRINT( LINK_QUIC_NET_DATA_SZ, 0UL ) ];

#define QUIC_CONN_MAX (8UL)
#define QUIC_HS_MAX   (8UL)
static __attribute__((aligned(4096))) uchar scratch_mem[ 163840 ];

static __attribute__((aligned(FD_CNC_ALIGN))) uchar server_cnc_mem[ FD_CNC_FOOTPRINT( 0UL ) ];
static __attribute__((aligned(FD_CNC_ALIGN))) uchar client_cnc_mem[ FD_CNC_FOOTPRINT( 0UL ) ];

static void
test_server_init( void ) {

  memset( topo, 0, sizeof(fd_topo_t) );

  /* Topo */

  fd_topo_tile_t * tile = &topo->tiles[0];
  ulong link_cnt = 0UL;
  ulong obj_cnt  = 0UL;
  ulong wksp_cnt = 0UL;

  tile->in_cnt = LINK_IN_CNT;

  tile->in_link_id[0] = link_cnt++;
  fd_topo_link_t * net_quic = &topo->links[ tile->in_link_id[0] ];
  strcpy( net_quic->name, "net_quic" );
  net_quic->mcache_obj_id = obj_cnt++;
  topo->objs[ net_quic->mcache_obj_id ].wksp_id = wksp_cnt++;
  net_quic->dcache_obj_id = obj_cnt++;
  topo->objs[ net_quic->dcache_obj_id ].wksp_id = wksp_cnt++;

  tile->out_cnt = LINK_OUT_CNT;

  tile->out_link_id[0] = link_cnt++;
  fd_topo_link_t * quic_txn = &topo->links[ tile->out_link_id[0] ];
  strcpy( quic_txn->name, "quic_verify" );  /* ugly: quic makes assumptions about downstream tile */
  quic_txn->mcache_obj_id = obj_cnt++;
  topo->objs[ quic_txn->mcache_obj_id ].wksp_id = wksp_cnt++;
  quic_txn->reasm_obj_id  = obj_cnt++;
  topo->objs[ quic_txn->reasm_obj_id  ].wksp_id = wksp_cnt++;

  tile->out_link_id[1] = link_cnt++;
  fd_topo_link_t * quic_net = &topo->links[ tile->out_link_id[1] ];
  strcpy( quic_net->name, "quic_net" );
  quic_net->mcache_obj_id = obj_cnt++;
  topo->objs[ quic_net->mcache_obj_id ].wksp_id = wksp_cnt++;
  quic_net->dcache_obj_id = obj_cnt++;
  topo->objs[ quic_net->dcache_obj_id ].wksp_id = wksp_cnt++;

  tile->tile_obj_id = obj_cnt++;
  fd_topo_obj_t * tile_obj = &topo->objs[ tile->tile_obj_id ];
  topo->objs[ tile->tile_obj_id ].wksp_id = wksp_cnt++;

  tile->quic.cnc_obj_id = obj_cnt++;
  topo->objs[ tile->quic.cnc_obj_id ].wksp_id = wksp_cnt++;

  /* End topo */
  topo->link_cnt = link_cnt;
  topo->obj_cnt  = obj_cnt;

  /* Constructors */

  tile->quic.max_concurrent_connections = QUIC_CONN_MAX;
  tile->quic.max_concurrent_handshakes  = QUIC_HS_MAX;

  net_quic->mcache = fd_mcache_join( fd_mcache_new( net_quic_mcache_mem, LINK_NET_QUIC_DEPTH, 0UL, 0UL ) );
  topo->objs[ net_quic->mcache_obj_id ].footprint = sizeof(net_quic_mcache_mem);
  topo->workspaces[ topo->objs[ net_quic->mcache_obj_id ].wksp_id ].wksp = (void *)net_quic_mcache_mem;
  FD_TEST( net_quic->mcache );

  net_quic->dcache = fd_dcache_join( fd_dcache_new( net_quic_dcache_mem, LINK_NET_QUIC_DATA_SZ, 0UL ) );
  topo->objs[ net_quic->dcache_obj_id ].footprint = sizeof(net_quic_dcache_mem);
  topo->workspaces[ topo->objs[ net_quic->dcache_obj_id ].wksp_id ].wksp = (void *)net_quic_dcache_mem;
  FD_TEST( net_quic->dcache );

  quic_txn->mcache = fd_mcache_join( fd_mcache_new( quic_txn_mcache_mem, LINK_QUIC_TXN_DEPTH, LINK_QUIC_TXN_APP_SZ, 0UL ) );
  FD_TEST( quic_txn->mcache );

  tile->quic.reasm_cnt = REASM_CNT;
  FD_LOG_INFO(( "fd_tpu_reasm_footprint(%lu,%lu)==%lu", LINK_QUIC_TXN_DEPTH, REASM_CNT, fd_tpu_reasm_footprint( LINK_QUIC_TXN_DEPTH, REASM_CNT ) ));
  FD_TEST( fd_tpu_reasm_footprint( LINK_QUIC_TXN_DEPTH, REASM_CNT )==REASM_FOOTPRINT );
  quic_txn->is_reasm = 1;
  quic_txn->reasm = fd_tpu_reasm_join( fd_tpu_reasm_new( reasm_mem, LINK_QUIC_TXN_DEPTH, REASM_CNT, 1UL ) );
  FD_TEST( quic_txn->reasm );

  quic_net->mcache = fd_mcache_join( fd_mcache_new( quic_net_mcache_mem, LINK_QUIC_NET_DEPTH, LINK_QUIC_NET_APP_SZ, 0UL ) );
  FD_TEST( quic_net->mcache );

  quic_net->dcache = fd_dcache_join( fd_dcache_new( quic_net_dcache_mem, LINK_QUIC_NET_DATA_SZ, 0UL ) );
  FD_TEST( quic_net->dcache );

  fd_cnc_signal( fd_cnc_join( server_cnc_mem ), FD_CNC_SIGNAL_BOOT );
  topo->objs[ tile->quic.cnc_obj_id ].offset    = (ulong)server_cnc_mem;
  topo->objs[ tile->quic.cnc_obj_id ].footprint = sizeof(server_cnc_mem);

  FD_TEST( !fd_tile_quic.loose_footprint );
  FD_LOG_INFO(( "fd_tile_quic.scratch_align()==%lu", fd_tile_quic.scratch_align() ));
  FD_LOG_INFO(( "fd_tile_quic.scratch_footprint(tile)==%lu", fd_tile_quic.scratch_footprint( tile ) ));
  FD_TEST( fd_ulong_is_aligned( (ulong)scratch_mem, fd_tile_quic.scratch_align() ) );
  FD_TEST( sizeof(scratch_mem)==fd_tile_quic.scratch_footprint( tile ) );
  tile_obj->offset    = (ulong)scratch_mem;
  tile_obj->footprint = sizeof(scratch_mem);

  tile->quic.ack_delay_millis             =    50;
  tile->quic.idle_timeout_millis          = 10000;
  tile->quic.quic_transaction_listen_port =  8000;

}

static __attribute__((aligned(FD_METRICS_ALIGN))) uchar server_metrics_mem[ FD_METRICS_FOOTPRINT( LINK_IN_CNT, LINK_OUT_CNT ) ];

static int
test_server_main( int     argc,
                  char ** argv ) {
  FD_TEST( argc==2 );
  fd_topo_t * topo = (fd_topo_t *)argv[0];
  fd_topo_tile_t * tile = (fd_topo_tile_t *)argv[1];
  fd_metrics_register( fd_metrics_join( fd_metrics_new( server_metrics_mem, LINK_IN_CNT, LINK_OUT_CNT ) ) );
  fd_tile_quic.privileged_init( topo, tile );
  fd_tile_quic.unprivileged_init( topo, tile );
  fd_tile_quic.run( topo, tile );
  return 0;
}

static fd_tile_exec_t *
test_server_start( ulong tile_idx ) {
  static char * argv[2] = { (char *)topo, (char *)(&topo->tiles[0]) };
  fd_tile_exec_t * exec = fd_tile_exec_new( tile_idx, test_server_main, 2, argv );
  if( FD_UNLIKELY( !exec ) ) FD_LOG_ERR(( "fd_tile_exec_new failed" ));
  return exec;
}

static __attribute__((aligned(FD_METRICS_ALIGN))) uchar client_metrics_mem[ FD_METRICS_FOOTPRINT( LINK_IN_CNT, LINK_OUT_CNT ) ];

struct client_ctx {
  fd_quic_t * quic;
  void *      rx_base;
  fd_cnc_t *  cnc;
  jmp_buf     bail;
};

typedef struct client_ctx client_ctx_t;

static void
client_during_housekeeping( client_ctx_t * ctx ) {
  ulong s = fd_cnc_signal_query( ctx->cnc );
  if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) longjmp( ctx->bail, 1 );
}

static void
client_during_frag( client_ctx_t * ctx,
                    ulong          in_idx FD_PARAM_UNUSED,
                    ulong          seq    FD_PARAM_UNUSED,
                    ulong          sig    FD_PARAM_UNUSED,
                    ulong          chunk,
                    ulong          sz ) {
  uchar * frag = fd_chunk_to_laddr( ctx->rx_base, chunk );
  fd_quic_process_packet( ctx->quic, frag, sz );
  fd_quic_service( ctx->quic );
}

#define STEM_NAME client_stem
#define STEM_BURST (1UL)
#define STEM_CALLBACK_DURING_HOUSEKEEPING client_during_housekeeping
#define STEM_CALLBACK_DURING_FRAG client_during_frag
#define STEM_CALLBACK_CONTEXT_TYPE  client_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(client_ctx_t)
#include "../stem/fd_stem.c"

static int
test_client_main( int     argc,
                  char ** argv ) {
  (void)argc; (void)argv;

  client_ctx_t ctx[1] = {{0}};

  fd_metrics_register( fd_metrics_join( fd_metrics_new( client_metrics_mem, 1, 1 ) ) );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 999, 0UL ) );

  fd_cnc_t *             cnc       = fd_cnc_join( client_cnc_mem );
  fd_frag_meta_t const * rx_mcache = fd_mcache_join( quic_net_mcache_mem );
  fd_frag_meta_t *       tx_mcache = fd_mcache_join( net_quic_mcache_mem );
  long                   lazy      = 1000L;

  static __attribute__((aligned(FD_FSEQ_ALIGN))) uchar rx_fseq_mem[ FD_FSEQ_FOOTPRINT ];
  ulong * fseq = fd_fseq_join( fd_fseq_new( rx_fseq_mem, 0UL ) );

  FD_LOG_INFO(( "client_stem_footprint(1,1,0)==%lu", client_stem_scratch_footprint( 1UL, 1UL, 0UL ) ));
  static __attribute__((aligned(FD_STEM_SCRATCH_ALIGN))) uchar scratch_mem[ 128 ];
  FD_TEST( sizeof(scratch_mem)==client_stem_scratch_footprint( 1UL, 1UL, 0UL ) );

  ctx->rx_base = quic_net_dcache_mem;
  ctx->cnc     = cnc;

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  if( !setjmp( ctx->bail ) ) {
    client_stem_run1( 1UL, &rx_mcache, &fseq, 1UL, &tx_mcache, 0UL, NULL, NULL, 1UL, lazy, rng, scratch_mem, ctx );
    __builtin_unreachable();
  }
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  fd_fseq_leave( fseq );
  fd_mcache_leave( rx_mcache );
  fd_mcache_leave( tx_mcache );
  fd_cnc_leave( cnc );

  return 0;
}

static fd_tile_exec_t *
test_client_start( ulong tile_idx ) {
  fd_tile_exec_t * exec = fd_tile_exec_new( tile_idx, test_client_main, 0, NULL );
  if( FD_UNLIKELY( !exec ) ) FD_LOG_ERR(( "fd_tile_exec_new failed" ));
  return exec;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( fd_tile_cnt()<3 ) ) FD_LOG_ERR(( "this unit test requires 3 tiles" ));

  fd_cnc_t * server_cnc = fd_cnc_join( fd_cnc_new( server_cnc_mem, 0UL, 0UL, 0L ) );
  fd_cnc_t * client_cnc = fd_cnc_join( fd_cnc_new( client_cnc_mem, 0UL, 0UL, 0L ) );

  test_server_init();
  fd_tile_exec_t * server_exec = test_server_start( 1UL );
  fd_tile_exec_t * client_exec = test_client_start( 2UL );

  FD_TEST( fd_cnc_wait( server_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );
  FD_TEST( fd_cnc_wait( client_cnc, FD_CNC_SIGNAL_BOOT, (long)5e9, NULL )==FD_CNC_SIGNAL_RUN );

  FD_TEST( !fd_cnc_open( server_cnc ) );
  FD_TEST( !fd_cnc_open( client_cnc ) );

  fd_cnc_signal( server_cnc, FD_CNC_SIGNAL_HALT );
  fd_cnc_signal( client_cnc, FD_CNC_SIGNAL_HALT );

  FD_TEST( fd_cnc_wait( server_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT );
  FD_TEST( fd_cnc_wait( client_cnc, FD_CNC_SIGNAL_HALT, (long)5e9, NULL )==FD_CNC_SIGNAL_BOOT );

  fd_cnc_close( server_cnc );
  fd_cnc_close( client_cnc );

  FD_TEST( !fd_tile_exec_delete( server_exec, NULL ) );
  FD_TEST( !fd_tile_exec_delete( client_exec, NULL ) );

  fd_cnc_delete( fd_cnc_leave( server_cnc ) );
  fd_cnc_delete( fd_cnc_leave( client_cnc ) );

  fd_halt();
  return 0;
}
