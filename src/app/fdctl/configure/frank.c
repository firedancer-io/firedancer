#include "configure.h"

#include "../../../tango/fd_tango.h"
#include "../../../tango/quic/fd_quic.h"
#include "../../../tango/xdp/fd_xsk_aio.h"

#include <linux/capability.h>

#define NAME "frank"

static void
init_perm( security_t *     security,
           config_t * const config ) {
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    check_cap( security, NAME, CAP_SYS_ADMIN, "enter a network namespace" );
}

#define INSERTER(arg, align, footprint, new) do {                                   \
    fd_wksp_t * wksp  = fd_wksp_containing( pod );                                  \
    ulong       gaddr = fd_wksp_alloc( wksp, ( align ), ( footprint ), 1 );         \
    void *      shmem = fd_wksp_laddr( wksp, gaddr );                               \
    (void)shmem;                                                                    \
    if( FD_UNLIKELY( !( new ) ) ) FD_LOG_ERR(( "failed to initialize workspace" )); \
    char name[ PATH_MAX ];                                                          \
    va_list args;                                                                   \
    va_start( args, arg );                                                          \
    vsnprintf( name, PATH_MAX, fmt, args );                                         \
    va_end( args );                                                                 \
    char buffer[ FD_WKSP_CSTR_MAX ];                                                \
    if( FD_UNLIKELY( !fd_wksp_cstr( wksp, gaddr, buffer ) ) )                       \
      FD_LOG_ERR(( "failed to get wksp gaddr for pod entry `%s`", name ));          \
    if( FD_UNLIKELY( !fd_pod_insert_cstr( pod, name, buffer ) ) )                   \
      FD_LOG_ERR(( "failed to insert value into pod for `%s`", name ));             \
  } while( 0 )

#define INSERTER2(arg, align, footprint, new) do {                                              \
    fd_wksp_t * wksp  = fd_wksp_containing( pod );                                              \
    ulong       gaddr = fd_wksp_alloc( wksp, ( align ), ( footprint ), 1 );                     \
    void *      shmem = fd_wksp_laddr( wksp, gaddr );                                           \
    if( FD_UNLIKELY( !( new ) ) ) FD_LOG_ERR(( "failed to initialize workspace" ));             \
    char name1[ PATH_MAX ];                                                                     \
    char name2[ PATH_MAX ];                                                                     \
    va_list args;                                                                               \
    va_start( args, arg );                                                                      \
    vsnprintf( name1, PATH_MAX, fmt1, args );                                                   \
    va_end( args );                                                                             \
    va_start( args, arg );                                                                      \
    vsnprintf( name2, PATH_MAX, fmt2, args );                                                   \
    va_end( args );                                                                             \
    char buffer[ FD_WKSP_CSTR_MAX ];                                                            \
    if( FD_UNLIKELY( !fd_pod_insert_cstr( pod, name1, fd_wksp_cstr( wksp, gaddr, buffer ) ) ) ) \
      FD_LOG_ERR(( "failed to initialize workspace" ));                                         \
    if( FD_UNLIKELY( !fd_pod_insert_cstr( pod, name2, fd_wksp_cstr( wksp, gaddr, buffer ) ) ) ) \
      FD_LOG_ERR(( "failed to initialize workspace" ));                                         \
  } while( 0 )

static void cnc( void * pod, char * fmt, ... ) {
  INSERTER( fmt,
            fd_cnc_align    (                                ),
            fd_cnc_footprint( 4032                           ),
            fd_cnc_new      ( shmem, 4032, 0, fd_tickcount() ) );
}

static void mcache( void * pod, char * fmt, ulong depth, ... ) {
  INSERTER( depth,
            fd_mcache_align    (                    ),
            fd_mcache_footprint( depth, 0           ),
            fd_mcache_new      ( shmem, depth, 0, 0 ) );
}

static void mcache2( void * pod, char * fmt1, char * fmt2, ulong depth, ... ) {
  INSERTER2( depth,
             fd_mcache_align    (                    ),
             fd_mcache_footprint( depth, 0           ),
             fd_mcache_new      ( shmem, depth, 0, 0 ) );
}

static void dcache( void * pod, char * fmt, ulong mtu, ulong depth, ulong app_sz, ... ) {
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1, 1 );
  INSERTER( app_sz,
            fd_dcache_align    (                          ),
            fd_dcache_footprint( data_sz, app_sz          ),
            fd_dcache_new      ( shmem,   data_sz, app_sz ) );
}

static void dcache2( void * pod, char * fmt1, char * fmt2, ulong mtu, ulong depth, ulong app_sz, ... ) {
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1, 1 );
  INSERTER2( app_sz,
             fd_dcache_align    (                          ),
             fd_dcache_footprint( data_sz, app_sz          ),
             fd_dcache_new      ( shmem,   data_sz, app_sz ) );
}

static void fseq( void * pod, char * fmt, ... ) {
  INSERTER( fmt,
            fd_fseq_align    (          ),
            fd_fseq_footprint(          ),
            fd_fseq_new      ( shmem, 0 ) );
}

static void fseq2( void * pod, char * fmt1, char * fmt2, ... ) {
  INSERTER2( fmt2,
             fd_fseq_align    (          ),
             fd_fseq_footprint(          ),
             fd_fseq_new      ( shmem, 0 ) );
}

static void tcache( void * pod, char * fmt, ulong depth, ... ) {
  INSERTER( depth,
            fd_tcache_align    (                 ),
            fd_tcache_footprint( depth, 0        ),
            fd_tcache_new      ( shmem, depth, 0 ) );
}

static void quic( void * pod, char * fmt, fd_quic_limits_t * limits, ... ) {
  INSERTER( limits,
            fd_quic_align    (               ),
            fd_quic_footprint( limits        ),
            fd_quic_new      ( shmem, limits ) );
}

static void xsk( void * pod, char * fmt, ulong frame_sz, ulong rx_depth, ulong tx_depth, ... ) {
  INSERTER( tx_depth,
            fd_xsk_align    (                                                            ),
            fd_xsk_footprint( frame_sz, rx_depth, rx_depth, tx_depth, tx_depth           ),
            fd_xsk_new      ( shmem,    frame_sz, rx_depth, rx_depth, tx_depth, tx_depth ) );
}

static void xsk_aio( void * pod, char * fmt, ulong tx_depth, ulong batch_count, ... ) {
  INSERTER( batch_count,
            fd_xsk_aio_align    (                                 ),
            fd_xsk_aio_footprint( tx_depth, batch_count           ),
            fd_xsk_aio_new      ( shmem,    tx_depth, batch_count ) );
}

static void alloc( void * pod, char * fmt, ulong align, ulong sz, ... ) {
  INSERTER( sz, align, sz, 1 );
}

#define VALUE( type, value ) do {                                 \
    char name[ PATH_MAX ];                                        \
    va_list args;                                                 \
    va_start( args, value );                                      \
    vsnprintf( name, PATH_MAX, fmt, args );                       \
    va_end( args );                                               \
    if( FD_UNLIKELY( !fd_pod_insert_##type( pod, fmt, value ) ) ) \
      FD_LOG_ERR(( "failed to initialize workspace" ));           \
  } while( 0 )

static void ulong1( void * pod, char * fmt, ulong value, ... ) {
  VALUE( ulong, value );
}

static void uint1( void * pod, char * fmt, uint value, ... ) {
  VALUE( uint, value );
}

/* need a dummy argument so we can locate va_args (value would be default
   promoted) */
static void ushort1( void * pod, char * fmt, ushort value, ulong dummy, ... ) { \
    char name[ PATH_MAX ];                                                      \
    va_list args;                                                               \
    va_start( args, dummy );                                                    \
    vsnprintf( name, PATH_MAX, fmt, args );                                     \
    va_end( args );                                                             \
    if( FD_UNLIKELY( !fd_pod_insert_ushort( pod, fmt, value ) ) )               \
      FD_LOG_ERR(( "failed to initialize workspace" ));                         \
}

static void buf( void * pod, char * fmt, void * value, ulong sz, ... ) {
  char name[ PATH_MAX ];
  va_list args;
  va_start( args, sz );
  vsnprintf( name, PATH_MAX, fmt, args );
  va_end( args );
  if( FD_UNLIKELY( !fd_pod_insert_buf( pod, fmt, value, sz ) ) )
    FD_LOG_ERR(( "failed to initialize workspace" ));
}

static void
init( config_t * const config ) {
  /* enter network namespace for bind. this is only needed for a check
     that the interface exists.. we can probably skip that */
  enter_network_namespace( config );

  char workspace[ FD_WKSP_CSTR_MAX ];
  snprintf1( workspace, FD_WKSP_CSTR_MAX, "%s.wksp", config->name );

  fd_wksp_t * wksp  = fd_wksp_attach( workspace );
  ulong       gaddr = fd_wksp_alloc( wksp, fd_pod_align(), fd_pod_footprint( 16384 ), 1 );
  void *      pod   = fd_wksp_laddr( wksp, gaddr );
  if( FD_UNLIKELY( !fd_pod_new( pod, 16384 ) ) ) FD_LOG_ERR(( "failed to initialize workspace" ));

  char pod_str[ FD_WKSP_CSTR_MAX ];
  if( FD_UNLIKELY( !fd_wksp_cstr( wksp, gaddr, pod_str ) ) ) FD_LOG_ERR(( "failed to initialize workspace" ));

  cnc   ( pod, "firedancer.main.cnc" );

  cnc   ( pod, "firedancer.pack.cnc" );
  mcache( pod, "firedancer.pack.out-mcache",           config->tiles.pack.max_pending_transactions );
  dcache( pod, "firedancer.pack.out-dcache",           4808, 6 * config->tiles.pack.max_pending_transactions, 0 );  // 6 should be  `(num_bank_threads+1) * max_pending_transactions + num_bank_threads`
  fseq  ( pod, "firedancer.pack.return-fseq" );
  ulong1( pod, "firedancer.pack.bank-cnt",             config->tiles.pack.solana_labs_bank_thread_count );
  ulong1( pod, "firedancer.pack.txnq-sz",              config->tiles.pack.max_pending_transactions );
  ulong1( pod, "firedancer.pack.cu-limit",             config->tiles.pack.solana_labs_bank_thread_compute_units_executed_per_second );
  ulong1( pod, "firedancer.pack.cu-est-tbl.bin-cnt",   4096 );
  ulong1( pod, "firedancer.pack.cu-est-tbl.footprint", 32 + 32 * 4096 );
  alloc ( pod, "firedancer.pack.cu-est-tbl.memory",    32, 32 + 32 * 4096 );

  cnc   ( pod, "firedancer.dedup.cnc",                 pod, wksp );
  tcache( pod, "firedancer.dedup.tcache",              config->tiles.dedup.signature_cache_size );
  mcache( pod, "firedancer.dedup.mcache",              config->tiles.verify.receive_buffer_size );
  fseq  ( pod, "firedancer.dedup.fseq" );

  for( uint i=0; i<config->layout.verify_tile_count; i++ ) {
    mcache2( pod, "firedancer.verifyin.v%uin.mcache",  "firedancer.quic.quic%u.mcache", config->tiles.verify.receive_buffer_size, i );
    dcache2( pod, "firedancer.verifyin.v%uin.dcache",  "firedancer.quic.quic%u.dcache", config->tiles.verify.mtu, config->tiles.verify.receive_buffer_size, config->tiles.verify.receive_buffer_size * 32, i );
    fseq2  ( pod, "firedancer.verifyin.v%uin.fseq",    "firedancer.quic.quic%u.fseq",   i );

    cnc    ( pod, "firedancer.verify.v%u.cnc",         i );
    mcache ( pod, "firedancer.verify.v%u.mcache",      config->tiles.verify.receive_buffer_size, i );
    dcache ( pod, "firedancer.verify.v%u.dcache",      config->tiles.verify.mtu, config->tiles.verify.receive_buffer_size, 0, i );
    fseq   ( pod, "firedancer.verify.v%u.fseq",        i );
  }

  fd_quic_limits_t limits = {
    .conn_cnt                                      = config->tiles.quic.max_concurrent_connections,
    .handshake_cnt                                 = config->tiles.quic.max_concurrent_handshakes,
    .conn_id_cnt                                   = config->tiles.quic.max_concurrent_connection_ids_per_connection,
    .conn_id_sparsity                              = 0.0,
    .inflight_pkt_cnt                              = config->tiles.quic.max_inflight_quic_packets,
    .tx_buf_sz                                     = config->tiles.quic.tx_buf_size,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_CLIENT ] = 0,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_BIDI_SERVER ] = 0,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT  ] = config->tiles.quic.max_concurrent_streams_per_connection,
    .stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_SERVER  ] = 0,
  };

  for( uint i=0; i<config->layout.verify_tile_count; i++) {
    cnc    ( pod, "firedancer.quic.quic%u.cnc",     i );
    quic   ( pod, "firedancer.quic.quic%u.quic",    &limits, i );
    xsk    ( pod, "firedancer.quic.quic%u.xsk",     2048, config->tiles.quic.xdp_rx_queue_size, config->tiles.quic.xdp_tx_queue_size, i );
    xsk_aio( pod, "firedancer.quic.quic%u.xsk_aio", config->tiles.quic.xdp_tx_queue_size, config->tiles.quic.xdp_aio_depth, i );

    char quic_xsk[ FD_WKSP_CSTR_MAX ];
    snprintf1( quic_xsk, FD_WKSP_CSTR_MAX, "firedancer.quic.quic%u.xsk", i );
    char const * quic_xsk_gaddr = fd_pod_query_cstr( pod,  quic_xsk, NULL );
    void *       shmem          = fd_wksp_map      ( quic_xsk_gaddr );
    if( FD_UNLIKELY( !fd_xsk_bind( shmem, config->name, config->tiles.quic.interface, i ) ) )
      FD_LOG_ERR(( "failed to bind xsk for quic tile %u", i ));
    fd_wksp_unmap( shmem );
  }

  uint1  ( pod, "firedancer.quic_cfg.ip_addr",         config->tiles.quic.ip_addr );
  ushort1( pod, "firedancer.quic_cfg.listen_port",     config->tiles.quic.listen_port, 0 );
  buf    ( pod, "firedancer.quic_cfg.src_mac_addr",    config->tiles.quic.mac_addr, 6 );
  ulong1 ( pod, "firedancer.quic_cfg.idle_timeout_ms", 1000 );

  char const * main_cnc = fd_pod_query_cstr( pod, "firedancer.main.cnc", NULL );
  if( FD_UNLIKELY( !main_cnc) )
    FD_LOG_ERR(( "failed to find main cnc in workspace" ));

  dump_vars( config, pod_str, main_cnc );
}

static configure_result_t
check( config_t * const config ) {
  (void)config;
  /* partially configured so the runner tries to perform `undo` every
     time as well */
  PARTIALLY_CONFIGURED( "frank must be reconfigured every launch" );
}

configure_stage_t frank = {
  .name            = NAME,
  /* we can't really verify if a frank workspace has been set up
     correctly, so if we are running it we just recreate it every time */
  .always_recreate = 1,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
