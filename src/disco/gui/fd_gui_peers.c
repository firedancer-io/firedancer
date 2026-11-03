#include "fd_gui_peers.h"
#include "fd_gui_printf.h"
#include "fd_gui_config_parse.h"
#include "fd_gui_metrics.h"
#include "../../disco/metrics/fd_metrics_base.h"
#include "../../ballet/json/fd_jtok.h"

#include <errno.h>
#include <unistd.h>

FD_IMPORT_BINARY( dbip_f, "src/disco/gui/dbip.bin.zst" );

#define LOGGING 0

#define FD_GUI_WFS_ACTIVITY_TIMEOUT_NANOS (15L*1000L*1000L*1000L)

FD_FN_CONST ulong
fd_gui_peers_align( void ) {
  ulong a = 128UL;
  a = fd_ulong_max( a, alignof(fd_gui_peers_ctx_t)              );
  a = fd_ulong_max( a, fd_gui_peers_live_table_align()          );
  a = fd_ulong_max( a, fd_gui_peers_node_info_pool_align()      );
  a = fd_ulong_max( a, fd_gui_peers_node_info_map_align()       );
  a = fd_ulong_max( a, fd_gui_peers_node_pubkey_map_align()     );
  a = fd_ulong_max( a, fd_gui_peers_node_sock_map_align()       );
  a = fd_ulong_max( a, alignof(fd_gui_peers_ws_conn_t)          );
  FD_TEST( fd_ulong_pow2_up( a )==a );
  return a;
}

/* geoip_frames splits the embedded database into its head and segment
   section frames (see fd_gui_peers.h).  seg_cnt follows from seg_sz
   (8+9*seg_cnt plus at most 3 pad bytes).  Returns 0 if malformed. */

static int
geoip_frames( ulong * head_sz,
              ulong * seg_sz,
              ulong * seg_cnt ) {
  ulong f0 = ZSTD_findFrameCompressedSize( dbip_f, dbip_f_sz );
  if( FD_UNLIKELY( ZSTD_isError( f0 ) || f0>=dbip_f_sz ) ) return 0;
  if( FD_UNLIKELY( ZSTD_findFrameCompressedSize( dbip_f+f0, dbip_f_sz-f0 )!=dbip_f_sz-f0 ) ) return 0;
  *head_sz = ZSTD_getFrameContentSize( dbip_f,    f0           );
  *seg_sz  = ZSTD_getFrameContentSize( dbip_f+f0, dbip_f_sz-f0 );
  if( FD_UNLIKELY( *head_sz>FD_GUI_GEOIP_BIN_MAX || *seg_sz>FD_GUI_GEOIP_BIN_MAX || *seg_sz<17UL ) ) return 0; /* also CONTENTSIZE_UNKNOWN/ERROR */
  *seg_cnt = (*seg_sz-8UL)/9UL;
  return 1;
}

FD_FN_PURE ulong
fd_gui_peers_footprint( ulong max_ws_conn_cnt ) {
  ulong info_chain_cnt   = fd_gui_peers_node_info_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE );
  ulong pubkey_chain_cnt = fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE );
  ulong sock_chain_cnt   = fd_gui_peers_node_sock_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_peers_ctx_t),             sizeof(fd_gui_peers_ctx_t)                                              );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_live_table_align(),         fd_gui_peers_live_table_footprint        ( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_info_pool_align(),     fd_gui_peers_node_info_pool_footprint    ( FD_CONTACT_INFO_TABLE_SIZE ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_info_map_align(),      fd_gui_peers_node_info_map_footprint     ( info_chain_cnt )             );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_pubkey_map_align(),    fd_gui_peers_node_pubkey_map_footprint   ( pubkey_chain_cnt )           );
  l = FD_LAYOUT_APPEND( l, fd_gui_peers_node_sock_map_align(),      fd_gui_peers_node_sock_map_footprint     ( sock_chain_cnt )             );
  l = FD_LAYOUT_APPEND( l, alignof(fd_gui_peers_ws_conn_t),         max_ws_conn_cnt*sizeof(fd_gui_peers_ws_conn_t)                          );

  ulong head_sz, seg_sz, seg_cnt;
  if( FD_UNLIKELY( !geoip_frames( &head_sz, &seg_sz, &seg_cnt ) ) ) return 0UL;
  l = FD_LAYOUT_APPEND( l, 16UL,                                    head_sz                                                                 );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                           fd_ulong_align_up( seg_cnt, FD_GUI_GEOIP_BLK_SEGS )/FD_GUI_GEOIP_BLK_SEGS*sizeof(uint) );

  return FD_LAYOUT_FINI( l, fd_gui_peers_align() );
}

static void
geoip_pread( int fd, void * dst, ulong sz, ulong off ) {
  if( FD_UNLIKELY( (long)sz!=pread( fd, dst, sz, (off_t)off ) ) )
    FD_LOG_ERR(( "pread(geoip,%lu,%lu) failed (%i-%s)", sz, off, errno, fd_io_strerror( errno ) ));
}

/* load_geoip decompresses the head frame into image (country codes are
   copied out, city names stay in place) and streams the segment frame
   through bounce into fd.  The segment section is then read back once
   to validate it and sample ip_db->idx. */

static void
load_geoip( ZSTD_DCtx *      dctx,
            uchar *          bounce,
            uchar *          image,
            ulong            head_sz,
            ulong            seg_sz,
            ulong            seg_cnt,
            uint *           idx,
            int              fd,
            fd_gui_ip_db_t * ip_db ) {
  ulong f0 = ZSTD_findFrameCompressedSize( dbip_f, dbip_f_sz );
  ulong decompressed_sz = 0UL;
  ulong compressed_sz   = 0UL;
  ulong err = ZSTD_decompressStream_simpleArgs( dctx, image, head_sz, &decompressed_sz, dbip_f, f0, &compressed_sz );
  if( FD_UNLIKELY( ZSTD_isError( err ) ) ) FD_LOG_ERR(( "ZSTD_decompressStream_simpleArgs failed (%s)", ZSTD_getErrorName( err ) ));
  if( FD_UNLIKELY( err!=0UL || decompressed_sz!=head_sz ) ) FD_LOG_ERR(( "dbip database truncated" ));

  uchar const * p   = image;
  uchar const * end = image+head_sz;

# define CHECK(n)   do { if( FD_UNLIKELY( (ulong)(end-p)<(ulong)(n) ) ) FD_LOG_ERR(( "dbip database corrupt (truncated)" )); } while(0)
# define ADVANCE(n) do { CHECK(n); p += (n); } while(0)

  CHECK( sizeof(ulong) );
  ulong country_code_cnt = FD_LOAD( ulong, p ); ADVANCE( sizeof(ulong) );
  FD_TEST( country_code_cnt && country_code_cnt<=FD_GUI_GEOIP_MAX_COUNTRY_CNT ); /* 255 reserved for unknown */
  for( ulong i=0UL; i<country_code_cnt; i++ ) {
    CHECK( 2UL );
    fd_memcpy( ip_db->country_code[ i ], p, 2UL ); ADVANCE( 2UL );
    ip_db->country_code[ i ][ 2 ] = '\0';
    if( FD_UNLIKELY( i && strcmp( ip_db->country_code[ i-1UL ], ip_db->country_code[ i ] )>0 ) )
      FD_LOG_ERR(( "country codes not sorted a=%s > b=%s i=%lu", ip_db->country_code[ i-1UL ], ip_db->country_code[ i ], i ));
  }

  CHECK( sizeof(ulong) );
  ulong city_name_cnt = FD_LOAD( ulong, p ); ADVANCE( sizeof(ulong) );
  FD_TEST( city_name_cnt<=FD_GUI_GEOIP_MAX_CITY_CNT );
  for( ulong i=0UL; i<city_name_cnt; i++ ) {
    uchar const * nul = memchr( p, '\0', fd_ulong_min( FD_GUI_GEOIP_MAX_CITY_NAME_SZ, (ulong)(end-p) ) );
    if( FD_UNLIKELY( !nul ) ) FD_LOG_ERR(( "dbip database corrupt (unterminated city name)" ));
    ip_db->city_name_off[ i ] = (uint)(p-image);
    ADVANCE( (ulong)(nul-p)+1UL );
    char const * prev = (char const *)image+ip_db->city_name_off[ i-!!i ];
    char const * cur  = (char const *)image+ip_db->city_name_off[ i ];
    if( FD_UNLIKELY( strcmp( prev, cur )>0 ) ) FD_LOG_ERR(( "city names not sorted a=%s > b=%s i=%lu", prev, cur, i ));
  }
  if( FD_UNLIKELY( fd_ulong_align_up( (ulong)(p-image), 4UL )!=head_sz ) ) FD_LOG_ERR(( "dbip database corrupt (head frame size)" ));

# undef ADVANCE
# undef CHECK

  FD_TEST( !ZSTD_isError( ZSTD_DCtx_reset( dctx, ZSTD_reset_session_only ) ) );
  ZSTD_inBuffer in = { .src=dbip_f+f0, .size=dbip_f_sz-f0, .pos=0UL };
  ulong off = 0UL;
  do {
    ZSTD_outBuffer out = { .dst=bounce, .size=FD_GUI_GEOIP_BOUNCE_SZ, .pos=0UL };
    err = ZSTD_decompressStream( dctx, &out, &in );
    if( FD_UNLIKELY( ZSTD_isError( err ) ) ) FD_LOG_ERR(( "ZSTD_decompressStream failed (%s)", ZSTD_getErrorName( err ) ));
    if( FD_UNLIKELY( off+out.pos>seg_sz || ( err && !out.pos && in.pos==in.size ) ) ) FD_LOG_ERR(( "dbip database corrupt (segment frame size)" ));
    if( FD_UNLIKELY( (long)out.pos!=pwrite( fd, bounce, out.pos, (off_t)off ) ) )
      FD_LOG_ERR(( "pwrite(geoip,%lu,%lu) failed (%i-%s)", out.pos, off, errno, fd_io_strerror( errno ) ));
    off += out.pos;
  } while( err );
  if( FD_UNLIKELY( off!=seg_sz || in.pos!=in.size ) ) FD_LOG_ERR(( "dbip database truncated" ));

  /* seg_cnt is implied by seg_sz; the header must agree */
  ulong hdr_cnt; geoip_pread( fd, &hdr_cnt, sizeof(ulong), 0UL );
  ulong country_off = 8UL+seg_cnt*sizeof(uint);
  ulong city_off    = country_off+fd_ulong_align_up( seg_cnt, 4UL );
  if( FD_UNLIKELY( hdr_cnt!=seg_cnt || city_off+seg_cnt*sizeof(uint)!=seg_sz ) ) FD_LOG_ERR(( "dbip database corrupt (segment count)" ));

  ulong const blk = FD_GUI_GEOIP_BOUNCE_SZ/sizeof(uint);
  uint * u = (uint *)bounce;
  uint prev = 0U;
  for( ulong i0=0UL; i0<seg_cnt; i0+=blk ) {
    ulong n = fd_ulong_min( blk, seg_cnt-i0 );
    geoip_pread( fd, u, n*sizeof(uint), 8UL+i0*sizeof(uint) );
    for( ulong j=0UL; j<n; j++ ) {
      ulong i = i0+j;
      if( FD_UNLIKELY( !i && u[ j ] ) )            FD_LOG_ERR(( "dbip database corrupt (first segment not 0)" ));
      if( FD_UNLIKELY( i && u[ j ]<=prev ) )        FD_LOG_ERR(( "dbip database corrupt (segments not sorted)" ));
      if( !(i%FD_GUI_GEOIP_BLK_SEGS) ) idx[ i/FD_GUI_GEOIP_BLK_SEGS ] = u[ j ];
      prev = u[ j ];
    }
  }
  for( ulong i0=0UL; i0<seg_cnt; i0+=FD_GUI_GEOIP_BOUNCE_SZ ) {
    ulong n = fd_ulong_min( FD_GUI_GEOIP_BOUNCE_SZ, seg_cnt-i0 );
    geoip_pread( fd, bounce, n, country_off+i0 );
    for( ulong j=0UL; j<n; j++ ) if( FD_UNLIKELY( bounce[ j ]!=UCHAR_MAX && bounce[ j ]>=country_code_cnt ) ) FD_LOG_ERR(( "dbip database corrupt (bad country idx)" ));
  }
  for( ulong i0=0UL; i0<seg_cnt; i0+=blk ) {
    ulong n = fd_ulong_min( blk, seg_cnt-i0 );
    geoip_pread( fd, u, n*sizeof(uint), city_off+i0*sizeof(uint) );
    for( ulong j=0UL; j<n; j++ ) if( FD_UNLIKELY( u[ j ]!=UINT_MAX && u[ j ]>=city_name_cnt ) ) FD_LOG_ERR(( "dbip database corrupt (bad city idx)" ));
  }

  ip_db->fd          = fd;
  ip_db->seg_cnt     = seg_cnt;
  ip_db->idx_cnt     = fd_ulong_align_up( seg_cnt, FD_GUI_GEOIP_BLK_SEGS )/FD_GUI_GEOIP_BLK_SEGS;
  ip_db->idx         = idx;
  ip_db->country_cnt = country_code_cnt;
  ip_db->city_cnt    = city_name_cnt;
  ip_db->image       = (char const *)image;
}

void *
fd_gui_peers_new( void *             shmem,
                  fd_http_server_t * http,
                  fd_topo_t const *  topo,
                  void *             dctx_scratch,
                  int                geoip_fd,
                  ulong              max_ws_conn_cnt,
                  char const *       wfs_expected_bank_hash_cstr,
                  ulong              seed,
                  long               now ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_peers_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong info_chain_cnt   = fd_gui_peers_node_info_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE );
  ulong pubkey_chain_cnt = fd_gui_peers_node_pubkey_map_chain_cnt_est( FD_CONTACT_INFO_TABLE_SIZE );
  ulong sock_chain_cnt   = fd_gui_peers_node_sock_map_chain_cnt_est  ( FD_CONTACT_INFO_TABLE_SIZE );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gui_peers_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_peers_ctx_t),             sizeof(fd_gui_peers_ctx_t)                                              );
  void * _live_table       = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_live_table_align(),         fd_gui_peers_live_table_footprint        ( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * _info_pool        = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_info_pool_align(),     fd_gui_peers_node_info_pool_footprint    ( FD_CONTACT_INFO_TABLE_SIZE ) );
  void * _info_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_info_map_align(),      fd_gui_peers_node_info_map_footprint     ( info_chain_cnt )             );
  void * _pubkey_map       = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_pubkey_map_align(),    fd_gui_peers_node_pubkey_map_footprint   ( pubkey_chain_cnt )           );
  void * _sock_map         = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_peers_node_sock_map_align(),      fd_gui_peers_node_sock_map_footprint     ( sock_chain_cnt )             );
  ctx->client_viewports    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gui_peers_ws_conn_t),         max_ws_conn_cnt*sizeof(fd_gui_peers_ws_conn_t)                          );
  ulong head_sz, seg_sz, seg_cnt;
  FD_TEST( geoip_frames( &head_sz, &seg_sz, &seg_cnt ) );
  ctx->dbip_image          = FD_SCRATCH_ALLOC_APPEND( l, 16UL,                                    head_sz                                                                 );
  uint * geoip_idx         = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                           fd_ulong_align_up( seg_cnt, FD_GUI_GEOIP_BLK_SEGS )/FD_GUI_GEOIP_BLK_SEGS*sizeof(uint) );
  ulong dctx_sz = ZSTD_estimateDStreamSize( 1 << FD_GUI_GEOIP_ZSTD_WINDOW_LOG );
  ZSTD_DCtx * zstd_dctx = ZSTD_initStaticDStream( dctx_scratch, dctx_sz );
  FD_TEST( zstd_dctx );
  uchar * geoip_bounce = (uchar *)dctx_scratch+fd_ulong_align_up( dctx_sz, 128UL );

    for( ulong i = 0UL; i<max_ws_conn_cnt; i++ ) ctx->client_viewports[ i ].connected = 0;

    ctx->http = http;
    ctx->topo = topo;

    ctx->wfs_enabled = !!strcmp( wfs_expected_bank_hash_cstr, "" );

    ctx->max_ws_conn_cnt   = max_ws_conn_cnt;
    ctx->open_ws_conn_cnt  = 0UL;
    ctx->active_ws_conn_id = ULONG_MAX;

    for( ulong i=0UL; i<2UL; i++ ) {
      ctx->epochs[ i ].epoch      = ULONG_MAX;
      ctx->epochs[ i ].stakes_cnt = 0UL;
    }
    ctx->delinquency.epoch     = ULONG_MAX;
    ctx->delinquency.reconcile = 0;

    ctx->next_client_nanos              = now;
    ctx->next_metric_rate_update_nanos  = now;
    ctx->next_gossip_stats_update_nanos = now;
    memset( &ctx->gossip_stats, 0, sizeof(ctx->gossip_stats) );

    for( ulong i = 0; i<FD_CONTACT_INFO_TABLE_SIZE; i++) {
      ctx->contact_info_table[ i ].row.valid = 0;
      ctx->contact_info_table[ i ].bw_dirty  = 0;
    }

    ctx->live_table      = fd_gui_peers_live_table_join( fd_gui_peers_live_table_new( _live_table, FD_CONTACT_INFO_TABLE_SIZE ) );
    fd_gui_peers_live_table_seed( ctx->contact_info_table, FD_CONTACT_INFO_TABLE_SIZE, seed );

    fd_gui_peers_bw_dirty_dlist_join( fd_gui_peers_bw_dirty_dlist_new( ctx->bw_dirty_dlist ) );

    ctx->node_info_pool  = fd_gui_peers_node_info_pool_join ( fd_gui_peers_node_info_pool_new ( _info_pool,  FD_CONTACT_INFO_TABLE_SIZE ) );
    ctx->node_info_map   = fd_gui_peers_node_info_map_join  ( fd_gui_peers_node_info_map_new  ( _info_map,   info_chain_cnt,   seed ) );
    ctx->node_pubkey_map = fd_gui_peers_node_pubkey_map_join( fd_gui_peers_node_pubkey_map_new( _pubkey_map, pubkey_chain_cnt, seed ) );
    ctx->node_sock_map   = fd_gui_peers_node_sock_map_join  ( fd_gui_peers_node_sock_map_new  ( _sock_map,   sock_chain_cnt,   seed ) );

    load_geoip( zstd_dctx, geoip_bounce, ctx->dbip_image, head_sz, seg_sz, seg_cnt, geoip_idx, geoip_fd, &ctx->dbip );

    ctx->wfs_peers_cnt = 0UL;
    ctx->wfs_peers_valid = 0;
    ctx->wfs_stakes_sent = 0;
    wfs_fresh_dlist_join( wfs_fresh_dlist_new( ctx->wfs_fresh_dlist ) );

    return shmem;
}

fd_gui_peers_ctx_t *
fd_gui_peers_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gui_peers_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_gui_peers_ctx_t * ctx = (fd_gui_peers_ctx_t *)shmem;

  return ctx;
}

static void
fd_gui_peers_gossip_stats_snap( fd_gui_peers_ctx_t *          peers,
                                fd_gui_peers_gossip_stats_t * gossip_stats,
                                long                          now ) {
  gossip_stats->sample_time = now;
  ulong gossvf_tile_cnt = fd_topo_tile_name_cnt( peers->topo, "gossvf"  );
  ulong gossip_tile_cnt = 1UL;

  gossip_stats->network_health_pull_response_msg_rx_success =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PULL_RESPONSE ) );
  gossip_stats->network_health_pull_response_msg_rx_failure =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_RESPONSE_LOOPBACK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) );
  gossip_stats->network_health_push_msg_rx_success =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PUSH ) );
  gossip_stats->network_health_push_msg_rx_failure =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PUSH_LOOPBACK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PUSH_NO_VALID_CRDS ) );
  gossip_stats->network_health_push_crds_rx_success =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_INSERTED_PUSH ) );
  gossip_stats->network_health_push_crds_rx_failure =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_STALE_PUSH ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_DUPLICATE_PUSH ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PUSH_SIGNATURE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PUSH_NO_CONTACT_INFO ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PUSH_SHRED_VERSION ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PUSH_INACTIVE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PUSH_WALLCLOCK ) );
  gossip_stats->network_health_pull_response_crds_rx_success =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_INSERTED_PULL_RESPONSE ) );
  gossip_stats->network_health_pull_response_crds_rx_failure =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_STALE_PULL_RESPONSE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_DUPLICATE_PULL_RESPONSE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PULL_RESPONSE_WALLCLOCK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PULL_RESPONSE_SIGNATURE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PULL_RESPONSE_NO_CONTACT_INFO ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PULL_RESPONSE_SHRED_VERSION ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, CRDS_RX_DROPPED_PULL_RESPONSE_INACTIVE ) );
  gossip_stats->network_health_push_crds_rx_duplicate =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_DUPLICATE_PUSH ) );
  gossip_stats->network_health_pull_response_crds_rx_duplicate =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_UPSERTED_DUPLICATE_PULL_RESPONSE ) );

  gossip_stats->network_health_total_stake = 0UL; /* todo ... fetch from RPC */
  gossip_stats->network_health_total_peers = 0UL; /* todo ... fetch from RPC */

  gossip_stats->network_health_connected_stake          = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_PEER_STAKE_LAMPORTS ) );
  gossip_stats->network_health_connected_staked_peers   = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_PEER_COUNT_STAKED ) );
  gossip_stats->network_health_connected_unstaked_peers = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_PEER_COUNT_UNSTAKED ) );

  ulong  peer_cnt = fd_ulong_min( fd_gui_peers_live_table_ele_cnt( peers->live_table ), FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT );
  ulong  rx_top[ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ]; double rx_val[ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ]; ulong rx_cnt = 0UL;
  ulong  tx_top[ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ]; double tx_val[ FD_GUI_PEERS_GOSSIP_TOP_PEERS_CNT ]; ulong tx_cnt = 0UL;
  gossip_stats->network_ingress_total_bytes_per_sec = 0UL;
  gossip_stats->network_egress_total_bytes_per_sec  = 0UL;

  for( fd_gui_peers_node_pubkey_map_iter_t iter = fd_gui_peers_node_pubkey_map_iter_init( peers->node_pubkey_map, peers->contact_info_table );
       !fd_gui_peers_node_pubkey_map_iter_done( iter, peers->node_pubkey_map, peers->contact_info_table );
       iter = fd_gui_peers_node_pubkey_map_iter_next( iter, peers->node_pubkey_map, peers->contact_info_table ) ) {
    fd_gui_peers_node_t const * cur = fd_gui_peers_node_pubkey_map_iter_ele_const( iter, peers->node_pubkey_map, peers->contact_info_table );
    ulong  idx = (ulong)(cur-peers->contact_info_table);
    double rx  = cur->row.gossvf_rx_sum.rate_ema.value;
    double tx  = cur->row.gossip_tx_sum.rate_ema.value;
    gossip_stats->network_ingress_total_bytes_per_sec += (long)rx;
    gossip_stats->network_egress_total_bytes_per_sec  += (long)tx;
    fd_gui_peers_top_insert( rx_top, rx_val, &rx_cnt, peer_cnt, idx, rx );
    fd_gui_peers_top_insert( tx_top, tx_val, &tx_cnt, peer_cnt, idx, tx );
  }

  gossip_stats->network_ingress_peer_sz = rx_cnt;
  for( ulong j=0UL; j<rx_cnt; j++ ) {
    fd_gui_peers_node_t const * cur = &peers->contact_info_table[ rx_top[ j ] ];
    fd_gui_config_parse_info_t * node_info = fd_gui_peers_node_info_map_ele_query( peers->node_info_map, &cur->row.pubkey, NULL, peers->node_info_pool );
    if( FD_LIKELY( node_info && !node_info->cleared ) ) FD_TEST( fd_cstr_printf_check( gossip_stats->network_ingress_peer_names[ j ], FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_NAME_SZ+1UL, NULL, "%s", node_info->name ) );
    else                         gossip_stats->network_ingress_peer_names[ j ][ 0 ] = '\0';
    gossip_stats->network_ingress_peer_bytes_per_sec[ j ] = (long)rx_val[ j ];
    fd_memcpy( &gossip_stats->network_ingress_peer_identities[ j ], cur->row.pubkey.uc, 32UL );
  }

  gossip_stats->network_ingress_total_bytes = fd_gui_metrics_gossip_total_ingress_bytes( peers->topo, gossvf_tile_cnt );

  gossip_stats->network_egress_peer_sz = tx_cnt;
  for( ulong j=0UL; j<tx_cnt; j++ ) {
    fd_gui_peers_node_t const * cur = &peers->contact_info_table[ tx_top[ j ] ];
    fd_gui_config_parse_info_t * node_info = fd_gui_peers_node_info_map_ele_query( peers->node_info_map, &cur->row.pubkey, NULL, peers->node_info_pool );
    if( FD_LIKELY( node_info && !node_info->cleared ) ) FD_TEST( fd_cstr_printf_check( gossip_stats->network_egress_peer_names[ j ], FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_NAME_SZ+1UL, NULL, "%s", node_info->name ) );
    else                         gossip_stats->network_egress_peer_names[ j ][ 0 ] = '\0';
    gossip_stats->network_egress_peer_bytes_per_sec[ j ] = (long)tx_val[ j ];
    fd_memcpy( &gossip_stats->network_egress_peer_identities[ j ], cur->row.pubkey.uc, 32UL );
  }

  gossip_stats->network_egress_total_bytes = fd_gui_metrics_gossip_total_egress_bytes( peers->topo, gossip_tile_cnt );

  gossip_stats->storage_capacity = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_CAPACITY ) );
  gossip_stats->storage_expired_cnt = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_EXPIRED ) );
  gossip_stats->storage_evicted_cnt = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_EVICTED ) );

  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_CONTACT_INFO_V1_IDX               ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_CONTACT_INFO_V1 )                   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VOTE_IDX                          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_VOTE )                              );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_LOWEST_SLOT_IDX                   ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_LOWEST_SLOT )                       );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_SNAPSHOT_HASHES_IDX               ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_SNAPSHOT_HASHES )                   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_ACCOUNTS_HASHES_IDX               ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_ACCOUNTS_HASHES )                   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_EPOCH_SLOTS_IDX                   ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_EPOCH_SLOTS )                       );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VERSION_V1_IDX                    ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_VERSION_V1 )                        );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VERSION_V2_IDX                    ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_VERSION_V2 )                        );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_NODE_INSTANCE_IDX                 ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_NODE_INSTANCE )                     );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_DUPLICATE_SHRED_IDX               ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_DUPLICATE_SHRED )                   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_INCREMENTAL_SNAPSHOT_HASHES_IDX   ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_INCREMENTAL_SNAPSHOT_HASHES )       );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_CONTACT_INFO_V2_IDX               ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_CONTACT_INFO_V2 )                   );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_RESTART_LAST_VOTED_FORK_SLOTS_IDX ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_RESTART_LAST_VOTED_FORK_SLOTS )     );
  gossip_stats->storage_active_cnt[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_RESTART_HEAVIEST_FORK_IDX         ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( GAUGE, GOSSIP, CRDS_USED_RESTART_HEAVIEST_FORK )             );

  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_CONTACT_INFO_V1_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_CONTACT_INFO_V1 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_CONTACT_INFO_V1 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VOTE_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_VOTE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_VOTE ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_LOWEST_SLOT_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_LOWEST_SLOT ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_LOWEST_SLOT ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_SNAPSHOT_HASHES_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_SNAPSHOT_HASHES ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_SNAPSHOT_HASHES ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_ACCOUNTS_HASHES_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_ACCOUNTS_HASHES ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_ACCOUNTS_HASHES ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_EPOCH_SLOTS_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_EPOCH_SLOTS ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_EPOCH_SLOTS ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VERSION_V1_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_VERSION_V1 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_VERSION_V1 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VERSION_V2_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_VERSION_V2 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_VERSION_V2 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_NODE_INSTANCE_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_NODE_INSTANCE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_NODE_INSTANCE ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_DUPLICATE_SHRED_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_DUPLICATE_SHRED ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_DUPLICATE_SHRED ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_INCREMENTAL_SNAPSHOT_HASHES_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_INCREMENTAL_SNAPSHOT_HASHES ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_INCREMENTAL_SNAPSHOT_HASHES ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_CONTACT_INFO_V2_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_CONTACT_INFO_V2 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_CONTACT_INFO_V2 ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_RESTART_LAST_VOTED_FORK_SLOTS_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_RESTART_LAST_VOTED_FORK_SLOTS ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_RESTART_LAST_VOTED_FORK_SLOTS ) );
  gossip_stats->storage_cnt_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_RESTART_HEAVIEST_FORK_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_RESTART_HEAVIEST_FORK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_RESTART_HEAVIEST_FORK ) );

  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_CONTACT_INFO_V1_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_CONTACT_INFO_V1 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_CONTACT_INFO_V1 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VOTE_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_VOTE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_VOTE ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_LOWEST_SLOT_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_LOWEST_SLOT ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_LOWEST_SLOT ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_SNAPSHOT_HASHES_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_SNAPSHOT_HASHES ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_SNAPSHOT_HASHES ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_ACCOUNTS_HASHES_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_ACCOUNTS_HASHES ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_ACCOUNTS_HASHES ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_EPOCH_SLOTS_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_EPOCH_SLOTS ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_EPOCH_SLOTS ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VERSION_V1_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_VERSION_V1 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_VERSION_V1 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_VERSION_V2_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_VERSION_V2 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_VERSION_V2 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_NODE_INSTANCE_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_NODE_INSTANCE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_NODE_INSTANCE ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_DUPLICATE_SHRED_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_DUPLICATE_SHRED ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_DUPLICATE_SHRED ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_INCREMENTAL_SNAPSHOT_HASHES_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_INCREMENTAL_SNAPSHOT_HASHES ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_INCREMENTAL_SNAPSHOT_HASHES ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_CONTACT_INFO_V2_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_CONTACT_INFO_V2 ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_CONTACT_INFO_V2 ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_RESTART_LAST_VOTED_FORK_SLOTS_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_RESTART_LAST_VOTED_FORK_SLOTS ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_RESTART_LAST_VOTED_FORK_SLOTS ) );
  gossip_stats->storage_bytes_tx[ FD_METRICS_ENUM_CRDS_VALUE_TYPE_V_RESTART_HEAVIEST_FORK_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PUSH_TX_BYTES_RESTART_HEAVIEST_FORK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, CRDS_PULL_RESPONSE_TX_BYTES_RESTART_HEAVIEST_FORK ) );

  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_REQUEST_IDX  ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_REQUEST ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_RESPONSE_IDX ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PULL_RESPONSE ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PUSH_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PUSH ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PING_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PING ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PONG_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PONG ) );
  gossip_stats->messages_bytes_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PRUNE_IDX         ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX( COUNTER, GOSSVF, MESSAGE_RX_BYTES_SUCCESS_PRUNE ) );

  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_REQUEST_IDX  ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PULL_REQUEST ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_REQUEST_NOT_CONTACT_INFO ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_REQUEST_LOOPBACK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_REQUEST_INACTIVE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_REQUEST_WALLCLOCK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_REQUEST_SIGNATURE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_REQUEST_SHRED_VERSION ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_REQUEST_MASK_BITS ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_RESPONSE_IDX ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PULL_RESPONSE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_RESPONSE_LOOPBACK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PULL_RESPONSE_NO_VALID_CRDS ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PUSH_IDX          ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PUSH ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PUSH_LOOPBACK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PUSH_NO_VALID_CRDS ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PING_IDX          ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PING ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PING_SIGNATURE ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PONG_IDX          ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PONG ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PONG_SIGNATURE ) );
  gossip_stats->messages_count_rx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PRUNE_IDX         ] =
      fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_SUCCESS_PRUNE ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PRUNE_DESTINATION ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PRUNE_WALLCLOCK ) )
    + fd_gui_metrics_sum_tiles_counter( peers->topo, "gossvf", gossvf_tile_cnt, MIDX(      COUNTER, GOSSVF, MESSAGE_RX_DROPPED_PRUNE_SIGNATURE ) );

  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_REQUEST_IDX  ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_REQUEST ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_RESPONSE_IDX ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PULL_RESPONSE ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PUSH_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PUSH ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PING_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PING ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PONG_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PONG ) );
  gossip_stats->messages_bytes_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PRUNE_IDX         ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_BYTES_PRUNE ) );

  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_REQUEST_IDX  ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_PULL_REQUEST ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_RESPONSE_IDX ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_PULL_RESPONSE ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PUSH_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_PUSH ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PING_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_PING ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PONG_IDX          ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_PONG ) );
  gossip_stats->messages_count_tx[ FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PRUNE_IDX         ] = fd_gui_metrics_sum_tiles_counter( peers->topo, "gossip", gossip_tile_cnt, MIDX( COUNTER, GOSSIP, MESSAGE_TX_PRUNE ) );
}

void
fd_gui_peers_handle_gossip_bw( fd_gui_peers_ctx_t *           peers,
                               fd_gui_gossip_bw_rec_t const * rec,
                               ulong                          rec_cnt,
                               int                            is_rx ) {
  for( ulong i=0UL; i<rec_cnt; i++ ) {
    fd_gossip_socket_t peer_sock = { .is_ipv6 = 0, .ip4 = rec[ i ].ip4, .port = rec[ i ].port };
    fd_gui_peers_node_t * peer = fd_gui_peers_node_sock_map_ele_query( peers->node_sock_map, &peer_sock, NULL, peers->contact_info_table );

    /* We set MAP_MULTI=1 since there are not guarantees that duplicates
       sockets won't exist. In cases where we see multiple sockets the
       update timestamp in fd_gui_peers_node_t is the tiebreaker */
    for( fd_gui_peers_node_t * p = peer; p!=NULL; p=(fd_gui_peers_node_t *)fd_gui_peers_node_sock_map_ele_next_const( p, NULL, peers->contact_info_table ) ) {
      if( p->row.update_time_nanos>peer->row.update_time_nanos ) peer = p;
    }

    if( FD_UNLIKELY( !peer ) ) continue; /* NOP, peer not known yet */

    ulong tag = rec[ i ].tag;
    if( FD_UNLIKELY( tag>=FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_CNT ) ) continue; /* NOP, unknown message kind */
    ulong rate_idx = tag-FD_METRICS_ENUM_GOSSIP_MESSAGE_TYPE_V_PULL_RESPONSE_IDX;
    if( FD_LIKELY( rate_idx<FD_GUI_PEERS_RATE_CNT ) ) fd_ptr_if( is_rx, &peer->row.gossvf_rx[ rate_idx ], &peer->row.gossip_tx[ rate_idx ] )->cur += rec[ i ].sz;
    fd_ptr_if( is_rx, (fd_gui_peers_metric_rate_t *)&peer->row.gossvf_rx_sum, (fd_gui_peers_metric_rate_t *)&peer->row.gossip_tx_sum )->cur += rec[ i ].sz;
    if( FD_UNLIKELY( !peer->bw_dirty ) ) {
      peer->bw_dirty = 1;
      fd_gui_peers_bw_dirty_dlist_ele_push_tail( peers->bw_dirty_dlist, peer, peers->contact_info_table );
    }
  }
}

void
fd_gui_peers_geoip_lookup( fd_gui_ip_db_t const * ip_db,
                           uint                   ip_addr,
                           uchar *                country_idx,
                           uint *                 city_idx ) {
  uint ip = fd_uint_bswap( ip_addr );

  /* Greatest block b with idx[b] <= ip, then greatest segment in it;
     idx[0]==seg_start[0]==0 */
  ulong lo = 0UL;
  ulong hi = ip_db->idx_cnt;
  while( hi-lo>1UL ) {
    ulong mid = (lo+hi)>>1;
    if( ip_db->idx[ mid ]<=ip ) lo = mid;
    else                        hi = mid;
  }
  ulong s0 = lo*FD_GUI_GEOIP_BLK_SEGS;
  uint  blk[ FD_GUI_GEOIP_BLK_SEGS ];
  hi = fd_ulong_min( FD_GUI_GEOIP_BLK_SEGS, ip_db->seg_cnt-s0 );
  geoip_pread( ip_db->fd, blk, hi*sizeof(uint), 8UL+s0*sizeof(uint) );
  lo = 0UL;
  while( hi-lo>1UL ) {
    ulong mid = (lo+hi)>>1;
    if( blk[ mid ]<=ip ) lo = mid;
    else                 hi = mid;
  }
  ulong seg = s0+lo;

  ulong country_off = 8UL+ip_db->seg_cnt*sizeof(uint);
  ulong city_off    = country_off+fd_ulong_align_up( ip_db->seg_cnt, 4UL );
  uchar country; geoip_pread( ip_db->fd, &country, 1UL,          country_off+seg              );
  uint  city;    geoip_pread( ip_db->fd, &city,    sizeof(uint), city_off+seg*sizeof(uint) );
  /* validated at boot; re-checked since the bytes come from disk */
  *country_idx = country<ip_db->country_cnt ? country : (uchar)UCHAR_MAX;
  *city_idx    = city   <ip_db->city_cnt    ? city    : UINT_MAX;
}

#define SORT_NAME wfs_peer_sort
#define SORT_KEY_T fd_gui_wfs_peer_t
#define SORT_BEFORE(a,b) (memcmp( (a).identity_key.uc, (b).identity_key.uc, 32UL )<0)
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME fd_gui_peers_voter_sort_iden_desc
#define SORT_KEY_T fd_gui_peers_voter_t
#define SORT_BEFORE(a,b) (memcmp( (a).weight.id_key.uc, (b).weight.id_key.uc, 32UL )>0)
#include "../../util/tmpl/fd_sort.c"

static void
wfs_handle_contact_info_update( fd_gui_peers_ctx_t * peers,
                                fd_pubkey_t const *  identity,
                                long                 now ) {
  if( FD_LIKELY( !peers->wfs_peers_valid ) ) return;

  ulong idx = wfs_peer_sort_split( peers->wfs_peers, peers->wfs_peers_cnt, (fd_gui_wfs_peer_t){ .identity_key = *identity } );
  if( FD_UNLIKELY( idx>=peers->wfs_peers_cnt || memcmp( identity->uc, peers->wfs_peers[ idx ].identity_key.uc, sizeof(fd_pubkey_t) ) ) ) return;

  fd_gui_wfs_peer_t * wp = &peers->wfs_peers[ idx ];
  wp->update_time_nanos = now;

  if( !wp->is_online ) {
    wp->is_online = 1;
    wfs_fresh_dlist_idx_push_tail( peers->wfs_fresh_dlist, idx, peers->wfs_peers );

    fd_gui_peers_printf_wfs_add( peers, &idx, 1UL );
    fd_http_server_ws_broadcast( peers->http );
  } else {
    wfs_fresh_dlist_idx_remove( peers->wfs_fresh_dlist, idx, peers->wfs_peers );
    wfs_fresh_dlist_idx_push_tail( peers->wfs_fresh_dlist, idx, peers->wfs_peers );
  }
}

static void
wfs_handle_contact_info_remove( fd_gui_peers_ctx_t * peers,
                                fd_pubkey_t const *  identity ) {
  if( FD_LIKELY( !peers->wfs_peers_valid ) ) return;

  ulong idx = wfs_peer_sort_split( peers->wfs_peers, peers->wfs_peers_cnt, (fd_gui_wfs_peer_t){ .identity_key = *identity } );
  if( FD_UNLIKELY( idx>=peers->wfs_peers_cnt || memcmp( identity->uc, peers->wfs_peers[ idx ].identity_key.uc, 32UL ) ) ) return;

  fd_gui_wfs_peer_t * wp = &peers->wfs_peers[ idx ];
  if( wp->is_online ) {
    wfs_fresh_dlist_idx_remove( peers->wfs_fresh_dlist, idx, peers->wfs_peers );
    wp->is_online = 0;

    fd_gui_peers_printf_wfs_remove( peers, &idx, 1UL );
    fd_http_server_ws_broadcast( peers->http );
  }
}

static inline fd_gui_peers_voter_t const *
fd_gui_peers_voter_best_for_identity( fd_gui_peers_voter_t const * voters,
                                      ulong                        voter_cnt,
                                      ulong *                      p_i ) {
  ulong i = *p_i;
  ulong j = i + 1UL;
  fd_gui_peers_voter_t const * best = &voters[ i ];
  while( j<voter_cnt && !memcmp( voters[ j ].weight.id_key.uc, best->weight.id_key.uc, sizeof(fd_pubkey_t) ) ) {
    if( voters[ j ].weight.stake>best->weight.stake ) best = &voters[ j ];
    j++;
  }
  *p_i = j;
  return best;
}

void
fd_gui_peers_handle_gossip_update( fd_gui_peers_ctx_t *               peers,
                                   fd_gossip_update_message_t const * update,
                                   long                               now ) {
    switch( update->tag ) {
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO: {
        if( FD_UNLIKELY( update->contact_info->idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected contact_info_idx %lu >= %lu", update->contact_info->idx, FD_CONTACT_INFO_TABLE_SIZE ));
        fd_gui_peers_node_t * peer = &peers->contact_info_table[ update->contact_info->idx ];
        if( FD_LIKELY( peer->row.valid ) ) {
#if LOGGING
          char _pk[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( update->origin, NULL, _pk );
          FD_LOG_WARNING(("UPDATE %lu pk=%s", update->contact_info->idx, _pk ));
#endif
#ifdef FD_GUI_USE_HANDHOLDING
          /* invariant checks */
          if( FD_UNLIKELY( memcmp( peer->row.pubkey.uc, update->origin, 32UL ) ) ) {
            char ci_pk[ FD_BASE58_ENCODED_32_SZ ];
            char og_pk[ FD_BASE58_ENCODED_32_SZ ];
            fd_base58_encode_32( peer->row.pubkey.uc, NULL, ci_pk );
            fd_base58_encode_32( update->origin, NULL, og_pk );

            /* A new pubkey is not allowed to overwrite an existing valid index */
            FD_LOG_ERR(( "invariant violation: peer->row.pubkey.uc=%s != update->origin=%s ", ci_pk, og_pk ));
          }
          FD_TEST( peer==fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, (fd_pubkey_t const * )update->origin, NULL, peers->contact_info_table ) );
          fd_gui_peers_node_t * peer_sock = fd_gui_peers_node_sock_map_ele_query( peers->node_sock_map, &peer->row.contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ], NULL, peers->contact_info_table );
          int found = 0;
          for( fd_gui_peers_node_t * p = peer_sock; !!p; p=(fd_gui_peers_node_t *)fd_gui_peers_node_sock_map_ele_next_const( p, NULL, peers->contact_info_table ) ) {
            if( peer==p ) {
              found = 1;
              break;
            }
          }
          FD_TEST( found );
#endif
          /* update does nothing */
          if( FD_UNLIKELY( fd_gossip_contact_info_eq( &peer->row.contact_info, update->contact_info->value ) ) ) {
            peer->row.wallclock_nanos   = FD_MILLI_TO_NANOSEC( update->wallclock );
            peer->row.update_time_nanos = now;
            wfs_handle_contact_info_update( peers, (fd_pubkey_t const *)update->origin, now );
            break;
          }

          fd_gui_peers_node_sock_map_idx_remove_fast( peers->node_sock_map, update->contact_info->idx, peers->contact_info_table );
          fd_gui_peers_live_table_idx_remove        ( peers->live_table,    update->contact_info->idx, peers->contact_info_table );

          peer->row.pubkey           = *(fd_pubkey_t *)update->origin;
          peer->row.contact_info     = *update->contact_info->value;
          peer->row.wallclock_nanos  = FD_MILLI_TO_NANOSEC( update->wallclock );
          peer->row.update_time_nanos = now;
          /* fetch and set country code */
          uint ip4 = peer->row.contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0 : peer->row.contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
          fd_gui_peers_geoip_lookup( &peers->dbip, ip4, &peer->row.country_code_idx, &peer->row.city_name_idx );

          fd_gui_peers_live_table_idx_insert        ( peers->live_table,    update->contact_info->idx, peers->contact_info_table );
          fd_gui_peers_node_sock_map_idx_insert     ( peers->node_sock_map, update->contact_info->idx, peers->contact_info_table );

          /* broadcast update to WebSocket clients */
          fd_gui_peers_printf_nodes( peers, (int[]){ FD_GUI_PEERS_NODE_UPDATE }, (ulong[]){ update->contact_info->idx }, 1UL );
          fd_http_server_ws_broadcast( peers->http );

          wfs_handle_contact_info_update( peers, (fd_pubkey_t const *)update->origin, now );
        } else {
#if LOGGING
          char _pk[ FD_BASE58_ENCODED_32_SZ ];
          fd_base58_encode_32( update->origin, NULL, _pk );
          FD_LOG_WARNING(( "ADD %lu pk=%s", update->contact_info->idx, _pk ));
#endif
          FD_TEST( !fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, fd_type_pun_const( update->origin ), NULL, peers->contact_info_table ) );
          peer->row.pubkey = *(fd_pubkey_t *)update->origin;
          memset( &peer->row.gossvf_rx,     0, sizeof(peer->row.gossvf_rx) );
          memset( &peer->row.gossip_tx,     0, sizeof(peer->row.gossip_tx) );
          memset( &peer->row.gossvf_rx_sum, 0, sizeof(peer->row.gossvf_rx_sum) );
          memset( &peer->row.gossip_tx_sum, 0, sizeof(peer->row.gossip_tx_sum) );
          for( ulong i=0UL; i<FD_GUI_PEERS_RATE_CNT; i++ ) {
            fd_gui_ema_init( &peer->row.gossvf_rx[ i ].rate_ema, now, FD_GUI_PEERS_EMA_HALF_LIFE_NS );
            fd_gui_ema_init( &peer->row.gossip_tx[ i ].rate_ema, now, FD_GUI_PEERS_EMA_HALF_LIFE_NS );
          }
          fd_gui_ema_init( &peer->row.gossvf_rx_sum.rate_ema, now, FD_GUI_PEERS_EMA_HALF_LIFE_NS );
          fd_gui_ema_init( &peer->row.gossip_tx_sum.rate_ema, now, FD_GUI_PEERS_EMA_HALF_LIFE_NS );
          peer->row.has_vote_info = 0;
          peer->row.stake = ULONG_MAX;
          peer->row.delinquent = 0;

          /* Backfill stake from already-received epoch data.  This
             handles the case where epoch info arrived before this peer
             was known via gossip.  If both epoch slots are populated,
             use the larger (current) epoch. */
          fd_vote_stake_weight_t best_weight = {0};
          int                    found       = 0;
          int   have_0 = peers->epochs[ 0 ].epoch!=ULONG_MAX;
          int   have_1 = peers->epochs[ 1 ].epoch!=ULONG_MAX;
          ulong ep = fd_ulong_if( have_0 & have_1, fd_ulong_if( peers->epochs[ 0 ].epoch>peers->epochs[ 1 ].epoch, 0UL, 1UL ), fd_ulong_if( have_0, 0UL, fd_ulong_if( have_1, 1UL, ULONG_MAX ) ) );
          if( FD_LIKELY( ep!=ULONG_MAX ) ) {
            fd_gui_peers_voter_t const * stakes = peers->epochs[ ep ].stakes;
            ulong                        cnt    = peers->epochs[ ep ].stakes_cnt;

            fd_gui_peers_voter_t query = { .weight = { .id_key = peer->row.pubkey } };
            ulong idx = fd_gui_peers_voter_sort_iden_desc_split( stakes, cnt, query );
            if( FD_LIKELY( idx<cnt && !memcmp( stakes[ idx ].weight.id_key.uc, peer->row.pubkey.uc, sizeof(fd_pubkey_t) ) ) ) {
              fd_gui_peers_voter_t const * best = fd_gui_peers_voter_best_for_identity( stakes, cnt, &idx );
              best_weight = best->weight;
              found       = 1;
            }
          }
          if( FD_UNLIKELY( found ) ) {
            peer->row.has_vote_info = 1;
            peer->row.vote_account  = best_weight.vote_key;
            peer->row.stake         = best_weight.stake;
            peers->delinquency.reconcile = 1;
          }

          fd_gui_config_parse_info_t * info =  fd_gui_peers_node_info_map_ele_query( peers->node_info_map, fd_type_pun_const(update->origin ), NULL, peers->node_info_pool );
          if( FD_LIKELY( info && !info->cleared ) ) fd_memcpy( peer->row.name, info->name, sizeof(info->name) );
          else                    peer->row.name[ 0 ] = '\0';

          peer->row.wallclock_nanos   = FD_MILLI_TO_NANOSEC( update->wallclock );

          peer->row.update_time_nanos = now;
          peer->row.contact_info      = *update->contact_info->value;

          /* fetch and set country code */
          uint ip4 = peer->row.contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0 : peer->row.contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
          fd_gui_peers_geoip_lookup( &peers->dbip, ip4, &peer->row.country_code_idx, &peer->row.city_name_idx );

          peer->row.valid = 1;

          /* update pubkey_map, sock_map */
          fd_gui_peers_node_sock_map_idx_insert  ( peers->node_sock_map,   update->contact_info->idx, peers->contact_info_table );
          fd_gui_peers_node_pubkey_map_idx_insert( peers->node_pubkey_map, update->contact_info->idx, peers->contact_info_table );

          /* update live tables */
          fd_gui_peers_live_table_idx_insert        ( peers->live_table,  update->contact_info->idx, peers->contact_info_table );

          fd_gui_printf_peers_view_resize( peers, fd_gui_peers_live_table_ele_cnt( peers->live_table ) );
          fd_http_server_ws_broadcast( peers->http );

          /* broadcast update to WebSocket clients */
          fd_gui_peers_printf_nodes( peers, (int[]){ FD_GUI_PEERS_NODE_ADD }, (ulong[]){ update->contact_info->idx }, 1UL );
          fd_http_server_ws_broadcast( peers->http );

          wfs_handle_contact_info_update( peers, (fd_pubkey_t const *)update->origin, now );
        }
        break;
      }
      case FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE: {
        if( FD_UNLIKELY( update->contact_info_remove->idx>=FD_CONTACT_INFO_TABLE_SIZE ) ) FD_LOG_ERR(( "unexpected remove_contact_info_idx %lu >= %lu", update->contact_info_remove->idx, FD_CONTACT_INFO_TABLE_SIZE ));
#if LOGGING
        char _pk[ FD_BASE58_ENCODED_32_SZ ];
        fd_base58_encode_32( update->origin, NULL, _pk );
        FD_LOG_WARNING(( "REMOVE %lu pk=%s",update->contact_info_remove->idx, _pk ));
#endif

        fd_gui_peers_node_t * peer = &peers->contact_info_table[ update->contact_info_remove->idx ];

#ifdef FD_GUI_USE_HANDHOLDING
        /* invariant checks */
        FD_TEST( peer->row.valid ); /* Should have already been in the table */
        FD_TEST( peer==fd_gui_peers_node_pubkey_map_ele_query_const( peers->node_pubkey_map, (fd_pubkey_t const * )update->origin, NULL, peers->contact_info_table ) );
        fd_gui_peers_node_t * peer_sock = fd_gui_peers_node_sock_map_ele_query( peers->node_sock_map, &peer->row.contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ], NULL, peers->contact_info_table );
        int found = 0;
        for( fd_gui_peers_node_t const * p = peer_sock; !!p; p=(fd_gui_peers_node_t const *)fd_gui_peers_node_sock_map_ele_next_const( p, NULL, peers->contact_info_table ) ) {
          if( peer==p ) {
            found = 1;
            break;
          }
        }
        FD_TEST( found );
#endif
        wfs_handle_contact_info_remove( peers, (fd_pubkey_t const *)update->origin );

        fd_gui_peers_live_table_idx_remove          ( peers->live_table,      update->contact_info_remove->idx, peers->contact_info_table );
        if( FD_UNLIKELY( peer->bw_dirty ) ) {
          fd_gui_peers_bw_dirty_dlist_idx_remove( peers->bw_dirty_dlist, update->contact_info_remove->idx, peers->contact_info_table );
          peer->bw_dirty = 0;
        }
        fd_gui_peers_node_sock_map_idx_remove_fast  ( peers->node_sock_map,   update->contact_info_remove->idx, peers->contact_info_table );
        fd_gui_peers_node_pubkey_map_idx_remove_fast( peers->node_pubkey_map, update->contact_info_remove->idx, peers->contact_info_table );
        peer->row.valid = 0;

        fd_gui_printf_peers_view_resize( peers, fd_gui_peers_live_table_ele_cnt( peers->live_table ) );
        fd_http_server_ws_broadcast( peers->http );

        /* broadcast update to WebSocket clients */
        fd_gui_peers_printf_nodes( peers, (int[]){ FD_GUI_PEERS_NODE_DELETE }, (ulong[]){ update->contact_info_remove->idx }, 1UL );
        fd_http_server_ws_broadcast( peers->http );
        break;
      }
      default: break;
    }
}

void
fd_gui_peers_handle_epoch_info( fd_gui_peers_ctx_t *        peers,
                                fd_epoch_info_msg_t const * epoch_info,
                                long                        now FD_PARAM_UNUSED ) {
  ulong epoch_idx = epoch_info->epoch % 2UL;
  if( FD_UNLIKELY( peers->epochs[ epoch_idx ].epoch!=ULONG_MAX && peers->epochs[ epoch_idx ].epoch>=epoch_info->epoch ) ) return;

  if( FD_UNLIKELY( epoch_info->staked_vote_cnt>MAX_STAKE_WEIGHTS ) )
    FD_LOG_ERR(( "epoch stakes exceed MAX_STAKE_WEIGHTS=%lu", MAX_STAKE_WEIGHTS ));
  if( FD_UNLIKELY( epoch_info->staked_id_cnt>MAX_STAKE_WEIGHTS ) )
    FD_LOG_ERR(( "epoch id weights exceed MAX_STAKE_WEIGHTS=%lu", MAX_STAKE_WEIGHTS ));

  fd_vote_stake_weight_t const * weights = fd_epoch_info_msg_stake_weights( epoch_info );

  ulong stakes_cnt = 0UL;
  for( ulong i=0UL; i<epoch_info->staked_vote_cnt; i++ ) {
    if( FD_UNLIKELY( fd_pubkey_check_zero( &weights[ i ].id_key ) ) ) continue;
    peers->epochs[ epoch_idx ].stakes[ stakes_cnt ] = (fd_gui_peers_voter_t){ .weight = weights[ i ] };
    stakes_cnt++;
  }
  peers->epochs[ epoch_idx ].epoch      = epoch_info->epoch;
  peers->epochs[ epoch_idx ].start_slot = epoch_info->start_slot;
  peers->epochs[ epoch_idx ].stakes_cnt = stakes_cnt;

  /* sort for deduplication */
  fd_gui_peers_voter_sort_iden_desc_inplace( peers->epochs[ epoch_idx ].stakes, peers->epochs[ epoch_idx ].stakes_cnt );

  ulong updated_cnt = 0UL;
  ulong i=0UL;
  while( i<peers->epochs[ epoch_idx ].stakes_cnt ) {
    fd_gui_peers_voter_t const * best = fd_gui_peers_voter_best_for_identity( peers->epochs[ epoch_idx ].stakes, peers->epochs[ epoch_idx ].stakes_cnt, &i );

    ulong peer_idx = fd_gui_peers_node_pubkey_map_idx_query(
        peers->node_pubkey_map, &best->weight.id_key, ULONG_MAX,
        peers->contact_info_table );
    if( FD_UNLIKELY( peer_idx==ULONG_MAX ) ) continue;

    fd_gui_peers_node_t * peer = &peers->contact_info_table[ peer_idx ];

    int vote_eq = peer->row.has_vote_info
               && !memcmp( peer->row.vote_account.uc, best->weight.vote_key.uc, sizeof(fd_pubkey_t) )
               && peer->row.stake==best->weight.stake;
    if( FD_LIKELY( vote_eq ) ) continue;

    fd_gui_peers_live_table_idx_remove( peers->live_table, peer_idx, peers->contact_info_table );

    peer->row.has_vote_info = 1;
    peer->row.vote_account  = best->weight.vote_key;
    peer->row.stake         = best->weight.stake;

    fd_gui_peers_live_table_idx_insert( peers->live_table, peer_idx, peers->contact_info_table );

    peers->scratch.actions[ updated_cnt ] = FD_GUI_PEERS_NODE_UPDATE;
    peers->scratch.idxs   [ updated_cnt ] = peer_idx;
    updated_cnt++;
  }
  if( FD_UNLIKELY( updated_cnt ) ) {
    peers->delinquency.reconcile = 1;
    fd_gui_peers_printf_nodes( peers, peers->scratch.actions, peers->scratch.idxs, updated_cnt );
    fd_http_server_ws_broadcast( peers->http );
  }
}

/* https://github.com/anza-xyz/agave/blob/v4.2.1/rpc-client-types/src/request.rs#L166 */
#define FD_GUI_PEERS_DELINQUENT_SLOT_DISTANCE 128UL

void
fd_gui_peers_handle_slot_completed( fd_gui_peers_ctx_t *      peers,
                                    ulong                     slot,
                                    ulong                     epoch,
                                    fd_block_footer_t const * footer ) {
  if( FD_UNLIKELY( slot<FD_NUM_SLOTS_FOR_REWARD ) ) return;
  ulong reward_slot = slot-FD_NUM_SLOTS_FOR_REWARD;

  ulong epoch_idx = epoch % 2UL;
  if( FD_UNLIKELY( peers->epochs[ epoch_idx ].epoch!=epoch || reward_slot<peers->epochs[ epoch_idx ].start_slot ) ) return;

  /* Forks can complete an epoch E block after an epoch E+1 one. */
  if( FD_UNLIKELY( peers->delinquency.epoch!=ULONG_MAX && epoch<peers->delinquency.epoch ) ) return;
  if( FD_UNLIKELY( peers->delinquency.epoch!=epoch ) ) {
    /* Ranks are remapped every epoch */
    fd_memset( peers->delinquency.last_voted, 0, sizeof(peers->delinquency.last_voted) );
    peers->delinquency.epoch        = epoch;
    peers->delinquency.last_settled = 0UL;
    peers->delinquency.stamp_since  = ULONG_MAX;
    peers->delinquency.reconcile    = 1;
  }
  peers->delinquency.last_settled = fd_ulong_max( peers->delinquency.last_settled, reward_slot );

  fd_bls_set_t reward_set[ fd_bls_set_word_cnt ];
  fd_bls_set_null( reward_set );
  if( FD_UNLIKELY( footer->has_skip_reward_cert  ) ) fd_bls_set_union( reward_set, reward_set, footer->skip_reward_cert.signer_set  );
  if( FD_LIKELY  ( footer->has_notar_reward_cert ) ) fd_bls_set_union( reward_set, reward_set, footer->notar_reward_cert.signer_set );
  if( FD_LIKELY( !fd_bls_set_is_null( reward_set ) && peers->delinquency.stamp_since==ULONG_MAX ) ) peers->delinquency.stamp_since = reward_slot;
  for( ulong rank=fd_bls_set_const_iter_init( reward_set );
       !fd_bls_set_const_iter_done( rank );
       rank=fd_bls_set_const_iter_next( reward_set, rank ) ) {
    peers->delinquency.last_voted[ rank ] = fd_ulong_max( peers->delinquency.last_voted[ rank ], reward_slot );
  }

  /* Until a full delinquency window has been watched this epoch, every
     validator would read delinquent, so keep the previous values instead. */
  if( FD_UNLIKELY( peers->delinquency.stamp_since==ULONG_MAX || peers->delinquency.last_settled<peers->delinquency.stamp_since+FD_GUI_PEERS_DELINQUENT_SLOT_DISTANCE ) ) return;

  ulong updated_cnt = 0UL;
  ulong i=0UL;
  while( i<peers->epochs[ epoch_idx ].stakes_cnt ) {
    fd_gui_peers_voter_t const * best = fd_gui_peers_voter_best_for_identity( peers->epochs[ epoch_idx ].stakes, peers->epochs[ epoch_idx ].stakes_cnt, &i );

    ulong peer_idx = fd_gui_peers_node_pubkey_map_idx_query(
        peers->node_pubkey_map, &best->weight.id_key, ULONG_MAX,
        peers->contact_info_table );
    if( FD_UNLIKELY( peer_idx==ULONG_MAX ) ) continue;
    fd_gui_peers_node_t * peer = &peers->contact_info_table[ peer_idx ];

    ushort rank       = best->weight.rank;
    int    delinquent = rank>=FD_BLS_SET_MAX || fd_ulong_sat_sub( peers->delinquency.last_settled, peers->delinquency.last_voted[ rank ] )>=FD_GUI_PEERS_DELINQUENT_SLOT_DISTANCE;
    if( FD_LIKELY( peer->row.delinquent==delinquent ) ) continue;
    peer->row.delinquent = delinquent;

    peers->scratch.actions[ updated_cnt ] = FD_GUI_PEERS_NODE_UPDATE;
    peers->scratch.idxs   [ updated_cnt ] = peer_idx;
    updated_cnt++;
  }

  /* Peers holding vote info from another epoch's stakes (e.g. dropped
     from this epoch's set) cannot sign this epoch's reward certs.  The
     loop above never visits them, so sweep the table whenever the set
     of such peers may have grown. */
  if( FD_UNLIKELY( peers->delinquency.reconcile ) ) {
    peers->delinquency.reconcile = 0;
    fd_gui_peers_voter_t const * stakes = peers->epochs[ epoch_idx ].stakes;
    ulong                        cnt    = peers->epochs[ epoch_idx ].stakes_cnt;
    for( ulong peer_idx=0UL; peer_idx<FD_CONTACT_INFO_TABLE_SIZE; peer_idx++ ) {
      fd_gui_peers_node_t * peer = &peers->contact_info_table[ peer_idx ];
      if( FD_LIKELY( !peer->row.valid || !peer->row.has_vote_info || peer->row.delinquent ) ) continue;

      fd_gui_peers_voter_t query = { .weight = { .id_key = peer->row.pubkey } };
      ulong idx = fd_gui_peers_voter_sort_iden_desc_split( stakes, cnt, query );
      if( FD_LIKELY( idx<cnt && !memcmp( stakes[ idx ].weight.id_key.uc, peer->row.pubkey.uc, sizeof(fd_pubkey_t) ) ) ) continue;
      peer->row.delinquent = 1;

      peers->scratch.actions[ updated_cnt ] = FD_GUI_PEERS_NODE_UPDATE;
      peers->scratch.idxs   [ updated_cnt ] = peer_idx;
      updated_cnt++;
    }
  }

  if( FD_UNLIKELY( updated_cnt ) ) {
    fd_gui_peers_printf_nodes( peers, peers->scratch.actions, peers->scratch.idxs, updated_cnt );
    fd_http_server_ws_broadcast( peers->http );
  }
}

void
fd_gui_peers_handle_config_account( fd_gui_peers_ctx_t *  peers,
                                    uchar const *         data,
                                    ulong                 sz,
                                    ulong                 slot ) {
  fd_gui_config_parse_info_t parsed[1];
  if( FD_UNLIKELY( !fd_gui_config_parse_validator_info( data, sz, parsed ) ) ) return;
  parsed->slot = slot;

  /* Snapshots can hold several copies of an identity's account, the
     incremental after the full: keep the newest.  Some nodes clear all
     the fields instead of deleting their on-chain account: that copy is
     kept too, so its slot still outranks older ones, but reads as no
     info. */
  parsed->cleared = parsed->name[ 0 ]=='\0' && parsed->details[ 0 ]=='\0' && parsed->website[ 0 ]=='\0' && parsed->icon_uri[ 0 ]=='\0' && parsed->keybase_username[ 0 ]=='\0';
  fd_gui_config_parse_info_t * info = fd_gui_peers_node_info_map_ele_query( peers->node_info_map, &parsed->pubkey, NULL, peers->node_info_pool );
  if( FD_UNLIKELY( info && info->slot>slot ) ) return;
  int had_info = info && !info->cleared;
  if( FD_UNLIKELY( !info ) ) {
    if( FD_UNLIKELY( !fd_gui_peers_node_info_pool_free( peers->node_info_pool ) ) ) {
      FD_LOG_WARNING(( "On-chain ConfigProgram accounts count exceeded %lu", FD_CONTACT_INFO_TABLE_SIZE ));
      return;
    }
    info = fd_gui_peers_node_info_pool_ele_acquire( peers->node_info_pool );
    info->pubkey = parsed->pubkey;
    fd_gui_peers_node_info_map_ele_insert( peers->node_info_map, info, peers->node_info_pool );
  }
  info->slot    = parsed->slot;
  info->cleared = parsed->cleared;
  fd_memcpy( info->name,             parsed->name,             sizeof(info->name)             );
  fd_memcpy( info->website,          parsed->website,          sizeof(info->website)          );
  fd_memcpy( info->details,          parsed->details,          sizeof(info->details)          );
  fd_memcpy( info->icon_uri,         parsed->icon_uri,         sizeof(info->icon_uri)         );
  fd_memcpy( info->keybase_username, parsed->keybase_username, sizeof(info->keybase_username) );
  if( FD_UNLIKELY( info->cleared && !had_info ) ) return;

  fd_gui_peers_node_t * peer = fd_gui_peers_node_pubkey_map_ele_query( peers->node_pubkey_map, &info->pubkey, NULL, peers->contact_info_table );
  if( FD_UNLIKELY( peer ) ) {
    fd_gui_peers_live_table_ele_remove( peers->live_table, peer, peers->contact_info_table );
    fd_cstr_ncpy( peer->row.name, info->cleared ? "" : info->name, sizeof(peer->row.name) );
    fd_gui_peers_live_table_ele_insert( peers->live_table, peer, peers->contact_info_table );
    fd_gui_peers_printf_nodes( peers, (int[]){ FD_GUI_PEERS_NODE_UPDATE }, (ulong[]){ (ulong)( peer-peers->contact_info_table ) }, 1UL );
    fd_http_server_ws_broadcast( peers->http );
  }
}

void
fd_gui_peers_start_wfs( fd_gui_peers_ctx_t *        peers,
                        fd_epoch_info_msg_t const * epoch_info,
                        long                        now ) {

  if( FD_LIKELY( !peers->wfs_enabled ) ) return;
  if( FD_LIKELY( peers->wfs_peers_valid ) ) return;

  /* Wait for supermajority uses the stakes of the epoch being
     resumed, which is the first epoch message replay sends at boot,
     the same list the gossip tile uses. */
  fd_stake_weight_t const * id_weights = fd_epoch_info_msg_id_weights( epoch_info );
  ulong id_cnt = epoch_info->staked_id_cnt;

  for( ulong i=0UL; i<id_cnt; i++ ) {
    peers->wfs_peers[ i ].identity_key = id_weights[ i ].key;
    peers->wfs_peers[ i ].stake        = id_weights[ i ].stake;
    peers->wfs_peers[ i ].fresh_prev   = ULONG_MAX;
    peers->wfs_peers[ i ].fresh_next   = ULONG_MAX;

    ulong peer_idx = fd_gui_peers_node_pubkey_map_idx_query( peers->node_pubkey_map, &id_weights[ i ].key, ULONG_MAX,peers->contact_info_table );
    if( peer_idx!=ULONG_MAX && peers->contact_info_table[ peer_idx ].row.update_time_nanos > now - FD_GUI_WFS_ACTIVITY_TIMEOUT_NANOS ) {
      peers->wfs_peers[ i ].is_online         = 1;
      peers->wfs_peers[ i ].update_time_nanos = peers->contact_info_table[ peer_idx ].row.update_time_nanos;
    } else {
      peers->wfs_peers[ i ].is_online         = 0;
      peers->wfs_peers[ i ].update_time_nanos = 0L;
    }
  }
  peers->wfs_peers_cnt = id_cnt;

  /* Restore invariant: sorted by identity key */
  wfs_peer_sort_inplace( peers->wfs_peers, peers->wfs_peers_cnt );

  wfs_fresh_dlist_join( wfs_fresh_dlist_new( peers->wfs_fresh_dlist ) );

  /* Emit the wait_for_supermajority.stakes message with stakes and
     infos.  By this point all config accounts have been processed so
     node_info_map is populated. */
  fd_gui_peers_printf_wfs_stakes( peers );
  fd_http_server_ws_broadcast( peers->http );
  peers->wfs_stakes_sent = 1;

  ulong added_cnt = 0UL;
  for( ulong i=0UL; i<peers->wfs_peers_cnt; i++ ) {
    /* Peers are technically added here not ordered by timestamp, but it's
       not an issue since a) all timestamps should be similar b) the dlist
       will eventually be correct as subsequent updates come in. */
    if( FD_UNLIKELY( peers->wfs_peers[ i ].is_online ) ) {
      peers->scratch.wfs_peers[ added_cnt++ ] = i;
      wfs_fresh_dlist_idx_push_tail( peers->wfs_fresh_dlist, i, peers->wfs_peers );
    }
  }
  if( FD_LIKELY( added_cnt ) ) {
    fd_gui_peers_printf_wfs_add( peers, peers->scratch.wfs_peers, added_cnt );
    fd_http_server_ws_broadcast( peers->http );
  }
  peers->wfs_peers_valid = 1;
}

static void
fd_gui_peers_viewport_snap( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  FD_TEST( peers->client_viewports[ ws_conn_id ].connected );
  peers->scratch.viewport_cnt = 0UL;
  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].row_cnt==0UL ) ) return; /* empty viewport */
  if( FD_UNLIKELY( peers->client_viewports[ ws_conn_id ].row_cnt>FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ ) ) FD_LOG_ERR(("row_cnt=%lu", peers->client_viewports[ ws_conn_id ].row_cnt ));

  for( fd_gui_peers_live_table_fwd_iter_t iter = fd_gui_peers_live_table_fwd_iter_init( peers->live_table, &peers->client_viewports[ ws_conn_id ].sort_key, peers->contact_info_table ), j = 0;
       !fd_gui_peers_live_table_fwd_iter_done( iter ) && j<peers->client_viewports[ ws_conn_id ].start_row+peers->client_viewports[ ws_conn_id ].row_cnt;
       iter = fd_gui_peers_live_table_fwd_iter_next( iter, peers->contact_info_table ), j++ ) {
    if( FD_LIKELY( j<peers->client_viewports[ ws_conn_id ].start_row ) ) continue;
    fd_gui_peers_node_t const * cur = fd_gui_peers_live_table_fwd_iter_ele_const( iter, peers->contact_info_table );

    ulong viewport_idx = j-peers->client_viewports[ ws_conn_id ].start_row;
    FD_TEST( viewport_idx<FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ );
    peers->scratch.viewport[ viewport_idx ] = cur->row;
    peers->scratch.viewport_cnt             = viewport_idx+1UL;
  }

  /* Capture the old baseline as the diff reference, then commit the new
     rows as the new baseline.  Both happen here, before any formatting,
     so fd_gui_printf_peers_viewport_update reads only from scratch. */
  fd_memcpy( peers->scratch.viewport_ref, peers->client_viewports[ ws_conn_id ].viewport, peers->scratch.viewport_cnt*sizeof(fd_gui_peers_row_t) );
  fd_memcpy( peers->client_viewports[ ws_conn_id ].viewport, peers->scratch.viewport, peers->scratch.viewport_cnt*sizeof(fd_gui_peers_row_t) );
}

static int
fd_gui_peers_request_scroll( fd_gui_peers_ctx_t * peers,
                             ulong                ws_conn_id,
                             ulong                request_id,
                             char const *         params,
                             ulong                params_sz ) {
  if( FD_UNLIKELY( !peers->client_viewports[ ws_conn_id ].connected ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  ulong _start_row = 0UL; int has_start_row = 0;
  ulong _row_cnt   = 0UL; int has_row_cnt   = 0;

  fd_jtok_t j[1]; fd_jtok_init( j, params, params_sz );
  fd_jtok_str_t key;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if(      fd_jtok_str_eq( &key, "start_row" ) ) { fd_jtok_ulong( j, &_start_row ); has_start_row = 1; }
    else if( fd_jtok_str_eq( &key, "row_cnt"   ) ) { fd_jtok_ulong( j, &_row_cnt   ); has_row_cnt   = 1; }
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) || !has_start_row || !has_row_cnt ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  if( FD_UNLIKELY( _row_cnt > FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ || _start_row > fd_gui_peers_live_table_ele_cnt( peers->live_table )-_row_cnt ) ) {
    fd_gui_printf_null_query_response( peers->http, "gossip", "query_scroll", request_id );
    FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
    return 0;
  }

  if( FD_UNLIKELY( (peers->client_viewports[ ws_conn_id ].start_row==_start_row || _row_cnt==0UL) && peers->client_viewports[ ws_conn_id ].row_cnt==_row_cnt ) ) {
    return 0; /* NOP, scroll window hasn't changed */
  }

  /* update the client's viewport */
  peers->client_viewports[ ws_conn_id ].start_row = _start_row;
  peers->client_viewports[ ws_conn_id ].row_cnt   = _row_cnt;

  fd_gui_peers_viewport_snap( peers, ws_conn_id );
  fd_gui_printf_peers_viewport_request( peers, "query_scroll", ws_conn_id, request_id );
  FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
  return 0;
}

static int
fd_gui_peers_request_sort( fd_gui_peers_ctx_t * peers,
                           ulong                ws_conn_id,
                           ulong                request_id,
                           char const *         params,
                           ulong                params_sz ) {
  if( FD_UNLIKELY( !peers->client_viewports[ ws_conn_id ].connected ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  fd_gui_peers_live_table_sort_key_t sort_key = {0};
  int has_col = 0;
  int has_dir = 0;

  fd_jtok_t j[1]; fd_jtok_init( j, params, params_sz );
  fd_jtok_str_t key;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if( fd_jtok_str_eq( &key, "col" ) ) {
      has_col = 1;
      ulong i = 0UL;
      fd_jtok_arr_enter( j );
      while( fd_jtok_arr_next( j ) ) {
        if( FD_UNLIKELY( i>=fd_gui_peers_live_table_col_cnt() ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
        char col_name[ 32UL ];
        fd_jtok_cstr( j, col_name, sizeof(col_name) );
        if( FD_UNLIKELY( fd_jtok_err( j ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
        sort_key.col[ i ] = fd_gui_peers_live_table_col_name_to_idx( peers->live_table, col_name );
        if( FD_UNLIKELY( sort_key.col[ i ]==ULONG_MAX ) ) {
          FD_LOG_WARNING(( "unexpected column name %s", col_name ));
          return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
        }
        i++;
      }
      if( FD_UNLIKELY( i!=fd_gui_peers_live_table_col_cnt() ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    } else if( fd_jtok_str_eq( &key, "dir" ) ) {
      has_dir = 1;
      ulong i = 0UL;
      fd_jtok_arr_enter( j );
      while( fd_jtok_arr_next( j ) ) {
        if( FD_UNLIKELY( i>=fd_gui_peers_live_table_col_cnt() ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
        long dir = 0L;
        fd_jtok_long( j, &dir );
        if( FD_UNLIKELY( fd_jtok_err( j ) || dir<-1L || dir>1L ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
        sort_key.dir[ i ] = (int)dir;
        i++;
      }
      if( FD_UNLIKELY( i!=fd_gui_peers_live_table_col_cnt() ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    }
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) || !has_col || !has_dir ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  if( FD_UNLIKELY( !fd_gui_peers_live_table_verify_sort_key( &sort_key ) ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  fd_gui_peers_live_table_sort_key_remove( peers->live_table, &peers->client_viewports[ ws_conn_id ].sort_key );
  peers->client_viewports[ ws_conn_id ].sort_key = sort_key;

  fd_gui_peers_viewport_snap( peers, ws_conn_id );
  fd_gui_printf_peers_viewport_request( peers, "query_sort", ws_conn_id, request_id );
  FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
  return 0;
}

int
fd_gui_peers_ws_message( fd_gui_peers_ctx_t * peers,
                         ulong                ws_conn_id,
                         uchar const *        data,
                         ulong                data_len ) {
  ulong         id        = 0UL; int has_id = 0;
  fd_jtok_str_t topic     = {0};
  fd_jtok_str_t key       = {0};
  char const *  params    = NULL;
  ulong         params_sz = 0UL;

  fd_jtok_t j[1]; fd_jtok_init( j, data, data_len );
  fd_jtok_str_t member;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &member ) ) {
    if(      fd_jtok_str_eq( &member, "id"     ) ) { fd_jtok_ulong( j, &id ); has_id = 1; }
    else if( fd_jtok_str_eq( &member, "topic"  ) ) fd_jtok_str  ( j, &topic );
    else if( fd_jtok_str_eq( &member, "key"    ) ) fd_jtok_str  ( j, &key );
    else if( fd_jtok_str_eq( &member, "params" ) ) {
      if( FD_UNLIKELY( fd_jtok_peek( j )!=FD_JTOK_OBJ ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
      fd_jtok_raw( j, &params, &params_sz );
    }
  }
  if( FD_UNLIKELY( fd_jtok_fini( j ) || !has_id || !topic.ptr || !key.ptr ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;

  if( FD_LIKELY( fd_jtok_str_eq( &topic, "gossip" ) && fd_jtok_str_eq( &key, "query_sort" ) ) ) {
    if( FD_UNLIKELY( !params ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    return fd_gui_peers_request_sort( peers, ws_conn_id, id, params, params_sz );
  } else if( FD_LIKELY( fd_jtok_str_eq( &topic, "gossip" ) && fd_jtok_str_eq( &key, "query_scroll" ) ) ) {
    if( FD_UNLIKELY( !params ) ) return FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST;
    return fd_gui_peers_request_scroll( peers, ws_conn_id, id, params, params_sz );
  }

  return FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD;
}

static void
fd_gui_peers_viewport_log( fd_gui_peers_ctx_t *  peers,
                           ulong                 ws_conn_id) {
  FD_TEST( peers->scratch.viewport_cnt<=FD_GUI_PEERS_WS_VIEWPORT_MAX_SZ );

  char out[ 1<<14 ];
  char * p = fd_cstr_init( out );

  p = fd_cstr_append_printf( p,
    "\n[Viewport] table_size=%lu max_viewport_size=%lu\n"
    "+-------+----------------+----------------+----------------+----------------+----------------------------------------------------+-----------------+\n"
    "| Row # | RX Push (bps)  | RX Pull (bps)  | TX Push (bps)  | TX Pull (bps)  | Pubkey                                             | IP Address      |\n"
    "+-------+----------------+----------------+----------------+----------------+----------------------------------------------------+-----------------+\n",
    fd_gui_peers_live_table_ele_cnt( peers->live_table ), peers->scratch.viewport_cnt );

  ulong start_row = peers->client_viewports[ ws_conn_id ].start_row;
  for( ulong i=0UL; i<peers->scratch.viewport_cnt; i++ ) {
    ulong j = start_row + i;
    fd_gui_peers_row_t const * cur = &peers->scratch.viewport[ i ];

    char pubkey_base58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( cur->pubkey.uc, NULL, pubkey_base58 );

    char peer_addr[ 16 ]; /* 255.255.255.255 + '\0' */
    uint ip4 = cur->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].is_ipv6 ? 0 : cur->contact_info.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ].ip4;
    FD_TEST(fd_cstr_printf_check( peer_addr, sizeof(peer_addr), NULL, FD_IP4_ADDR_FMT,
                                  FD_IP4_ADDR_FMT_ARGS( ip4 ) ) );

    long cur_egress_push_bps           = (long)cur->gossip_tx[ FD_GUI_PEERS_RATE_PUSH ].rate_ema.value;
    long cur_ingress_push_bps          = (long)cur->gossvf_rx[ FD_GUI_PEERS_RATE_PUSH ].rate_ema.value;
    long cur_egress_pull_response_bps  = (long)cur->gossip_tx[ FD_GUI_PEERS_RATE_PULL_RESPONSE ].rate_ema.value;
    long cur_ingress_pull_response_bps = (long)cur->gossvf_rx[ FD_GUI_PEERS_RATE_PULL_RESPONSE ].rate_ema.value;

    p = fd_cstr_append_printf( p,
                               "| %5lu | %14ld | %14ld | %14ld | %14ld | %-50s | %-15s |\n",
                               j,
                               cur_ingress_push_bps,
                               cur_ingress_pull_response_bps,
                               cur_egress_push_bps,
                               cur_egress_pull_response_bps,
                               pubkey_base58,
                               peer_addr );
  }
  p = fd_cstr_append_printf(p, "+-------+----------------+----------------+----------------+----------------+----------------------------------------------------+-----------------+" );
  fd_cstr_fini( p );
  FD_LOG_NOTICE(( "%s", out ));
}

static void
fd_gui_peers_ws_conn_rr_grow( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  if( FD_UNLIKELY( !peers->open_ws_conn_cnt ) ) peers->active_ws_conn_id = ws_conn_id;
  peers->open_ws_conn_cnt++;
}

static void
fd_gui_peers_ws_conn_rr_shrink( fd_gui_peers_ctx_t * peers, ulong ws_conn_id ) {
  peers->open_ws_conn_cnt--;

  if( FD_UNLIKELY( peers->open_ws_conn_cnt && peers->active_ws_conn_id==ws_conn_id ) ) {
    for( ulong i=1UL; i<peers->max_ws_conn_cnt+1UL; i++ ) {
      ulong next_ws_conn_id = (ws_conn_id + i) % peers->max_ws_conn_cnt;
      if( FD_UNLIKELY( peers->client_viewports[ next_ws_conn_id ].connected ) ) {
        peers->active_ws_conn_id = next_ws_conn_id;
        break;
      }
    }
  }
}

static inline double
peer_ema_new_weight( double weight,
                     double alpha ) {
  return fmax( alpha + (1.0 - alpha) * weight, DBL_EPSILON );
}

static inline double
peer_ema_advance( fd_gui_ema_t * ema,
                  long           now,
                  double         sample,
                  long           dt,
                  double         alpha,
                  double         weight,
                  double         new_weight ) {
  if( FD_UNLIKELY( dt<=0L ) ) return ema->value;
  ema->value = (alpha * sample + (1.0 - alpha) * weight * ema->value) / new_weight;
  ema->weight            = new_weight;
  ema->last_update_nanos = now;
  return ema->value;
}

static inline void
peer_prefetchw( void const * lo,
                void const * hi ) { /* the lines holding [lo,hi) */
  for( ulong p=(ulong)lo & ~63UL; p<(ulong)hi; p+=64UL ) __builtin_prefetch( (void const *)p, 1, 3 );
}

static inline void
peer_rate_prefetch( fd_gui_peers_node_t const * table,
                    ulong                       idx ) {
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return; /* dlist null idx */
  fd_gui_peers_node_t const * peer = &table[ idx ];
  peer_prefetchw( peer->row.gossvf_rx,     &peer->row.gossip_tx_sum+1 );
  peer_prefetchw( &peer->dlist_live_table, peer+1                     );
}

void
fd_gui_peers_rate_update( fd_gui_peers_ctx_t * peers,
                          long                 now ) {
  double window = (double)(now - (peers->next_metric_rate_update_nanos - (FD_GUI_PEERS_METRIC_RATE_UPDATE_INTERVAL_MILLIS * 1000000L)));

  /* a peer's filters share one step; cache alpha across peers */
  long   alpha_dt = 0L;
  double alpha    = 0.0;

  /* prefetch two peers ahead (removing a node never rewrites the
     next node's links) */
  ulong idx = fd_gui_peers_bw_dirty_dlist_iter_fwd_init( peers->bw_dirty_dlist, peers->contact_info_table );
  ulong pf_idx = idx;
  peer_rate_prefetch( peers->contact_info_table, pf_idx );
  if( FD_LIKELY( pf_idx!=ULONG_MAX ) ) {
    pf_idx = fd_gui_peers_bw_dirty_dlist_iter_fwd_next( pf_idx, peers->bw_dirty_dlist, peers->contact_info_table );
    peer_rate_prefetch( peers->contact_info_table, pf_idx );
  }
  while( !fd_gui_peers_bw_dirty_dlist_iter_done( idx, peers->bw_dirty_dlist, peers->contact_info_table ) ) {
    fd_gui_peers_node_t * peer = &peers->contact_info_table[ idx ];
    ulong next_idx = fd_gui_peers_bw_dirty_dlist_iter_fwd_next( idx, peers->bw_dirty_dlist, peers->contact_info_table );
    if( FD_LIKELY( pf_idx!=ULONG_MAX ) ) {
      pf_idx = fd_gui_peers_bw_dirty_dlist_iter_fwd_next( pf_idx, peers->bw_dirty_dlist, peers->contact_info_table );
      peer_rate_prefetch( peers->contact_info_table, pf_idx );
    }

    fd_gui_ema_t const * ema0 = &peer->row.gossvf_rx[ 0 ].rate_ema;
    long dt = now - ema0->last_update_nanos;
    if( FD_UNLIKELY( dt>0L && dt!=alpha_dt ) ) {
      alpha_dt = dt;
      alpha    = fd_gui_ema_alpha( dt, ema0->half_life_nanos );
    }
    double weight     = ema0->weight;
    double new_weight = peer_ema_new_weight( weight, alpha );

    /* optimization: no need to remove / re-insert if the rates haven't
       changed */
    fd_gui_peers_metric_rate_t const * sum[ 2 ] = { &peer->row.gossvf_rx_sum, &peer->row.gossip_tx_sum };
    long other[ 2 ] = { (long)sum[ 0 ]->cur - (long)sum[ 0 ]->ref, (long)sum[ 1 ]->cur - (long)sum[ 1 ]->ref }; /* untracked types after the loop */
    int  change  = 0;
    int  pending = other[ 0 ] || other[ 1 ]; /* bytes counted since the last rate update */
    for( ulong i=0UL; !change && i<2UL*FD_GUI_PEERS_RATE_CNT; i++ ) {
      fd_gui_peers_metric_rate_t * metric = i<FD_GUI_PEERS_RATE_CNT ? &peer->row.gossvf_rx[ i ] : &peer->row.gossip_tx[ i-FD_GUI_PEERS_RATE_CNT ];
      other[ i/FD_GUI_PEERS_RATE_CNT ] -= (long)metric->cur - (long)metric->ref;
      int has_bytes = metric->cur!=metric->ref;
      if( FD_LIKELY( !has_bytes && metric->rate_ema.value==0.0 ) ) continue; /* don't update zero-bandwith peers */
      if( FD_UNLIKELY( metric->rate_ema.value!=0.0 ) ) { change = 1; break; }
      long new_rate = (long)(((double)((long)metric->cur - (long)metric->ref) * 1e9 / window));
      fd_gui_ema_t cpy = metric->rate_ema;
      long new_rate_ema = (long)peer_ema_advance( &cpy, now, (double)new_rate, dt, alpha, weight, new_weight );
      if( FD_LIKELY( new_rate_ema==0L ) ) continue;
      change = 1;
    }
    /* untracked types: new bytes as a zero ema sees them, then settle
       while the total is above the snap threshold */
    for( ulong d=0UL; !change && d<2UL; d++ ) {
      if( FD_UNLIKELY( sum[ d ]->rate_ema.value>=100.0 ) ) { change = 1; break; }
      if( FD_LIKELY( !other[ d ] ) ) continue;
      fd_gui_ema_t zero = {0};
      change = 0L!=(long)peer_ema_advance( &zero, now, (double)(long)((double)other[ d ] * 1e9 / window), dt, alpha, weight, new_weight );
    }

    if( !change ) {
      if( FD_LIKELY( !pending ) ) {
        fd_gui_peers_bw_dirty_dlist_idx_remove( peers->bw_dirty_dlist, idx, peers->contact_info_table );
        peer->bw_dirty = 0;
      }
      idx = next_idx;
      continue;
    }

    /* live_table */
    fd_gui_peers_live_table_ele_remove( peers->live_table, peer, peers->contact_info_table );
    for( ulong i=0UL; i<FD_GUI_PEERS_RATE_CNT; i++ ) {
      fd_gui_peers_metric_rate_t * metric = &peer->row.gossvf_rx[ i ];
      long new_rate = (long)(((double)((long)metric->cur - (long)metric->ref) * 1e9 / window));
      double new_rate_ema = peer_ema_advance( &metric->rate_ema, now, (double)new_rate, dt, alpha, weight, new_weight );
      metric->rate_ema.value = fd_double_if( new_rate_ema<100.0, 0.0, new_rate_ema ); /* snap near-zero ema to zero. 100 bytes/s threshold */
      metric->ref       = metric->cur;
      metric->update_timestamp_ns = now;
    }

    for( ulong i=0UL; i<FD_GUI_PEERS_RATE_CNT; i++ ) {
      fd_gui_peers_metric_rate_t * metric = &peer->row.gossip_tx[ i ];
      long new_rate = (long)(((double)((long)metric->cur - (long)metric->ref) * 1e9 / window));
      double new_rate_ema = peer_ema_advance( &metric->rate_ema, now, (double)new_rate, dt, alpha, weight, new_weight );
      metric->rate_ema.value = fd_double_if( new_rate_ema<100.0, 0.0, new_rate_ema ); /* snap near-zero ema to zero. 100 bytes/s threshold */
      metric->ref       = metric->cur;
      metric->update_timestamp_ns = now;
    }
    fd_gui_peers_live_table_ele_insert( peers->live_table, peer, peers->contact_info_table );

    /* bandwidth totals, read by the gossip stats snapshot */
    peer_ema_advance( &peer->row.gossvf_rx_sum.rate_ema, now, (double)((long)peer->row.gossvf_rx_sum.cur - (long)peer->row.gossvf_rx_sum.ref) * 1e9 / window, dt, alpha, weight, new_weight );
    peer->row.gossvf_rx_sum.ref      = peer->row.gossvf_rx_sum.cur;
    peer->row.gossvf_rx_sum.update_timestamp_ns = now;

    peer_ema_advance( &peer->row.gossip_tx_sum.rate_ema, now, (double)((long)peer->row.gossip_tx_sum.cur - (long)peer->row.gossip_tx_sum.ref) * 1e9 / window, dt, alpha, weight, new_weight );
    peer->row.gossip_tx_sum.ref      = peer->row.gossip_tx_sum.cur;
    peer->row.gossip_tx_sum.update_timestamp_ns = now;

    idx = next_idx;
  }
}

static int
fd_gui_peers_ws_conn_rr_advance( fd_gui_peers_ctx_t * peers, long now ) {
  if( FD_LIKELY( !peers->open_ws_conn_cnt || now <= peers->next_client_nanos ) ) return 0;

  for( ulong i=1UL; i<peers->max_ws_conn_cnt+1UL; i++ ) {
    ulong next_ws_conn_id = (peers->active_ws_conn_id + i) % peers->max_ws_conn_cnt;
    if( FD_UNLIKELY( peers->client_viewports[ next_ws_conn_id ].connected ) ) {
      peers->active_ws_conn_id = next_ws_conn_id;
      break;
    }
  }
  return 1;
}


long
fd_gui_peers_next_deadline( fd_gui_peers_ctx_t const * peers ) {
  long due = fd_long_min( peers->next_metric_rate_update_nanos, peers->next_gossip_stats_update_nanos );
  if( FD_UNLIKELY( peers->open_ws_conn_cnt ) ) due = fd_long_min( due, peers->next_client_nanos+1L ); /* fires on now>next */
  return due;
}

int
fd_gui_peers_poll( fd_gui_peers_ctx_t * peers, long now ) {
  int did_work = 0;

  ulong evicted_cnt = 0UL;
  while( FD_UNLIKELY( peers->wfs_peers_valid && !wfs_fresh_dlist_is_empty( peers->wfs_fresh_dlist, peers->wfs_peers ) ) ) {
    ulong head_idx = wfs_fresh_dlist_idx_peek_head( peers->wfs_fresh_dlist, peers->wfs_peers );
    fd_gui_wfs_peer_t * oldest = &peers->wfs_peers[ head_idx ];
    if( oldest->update_time_nanos > now - FD_GUI_WFS_ACTIVITY_TIMEOUT_NANOS ) break;

    wfs_fresh_dlist_idx_pop_head( peers->wfs_fresh_dlist, peers->wfs_peers );
    oldest->is_online = 0;

    peers->scratch.wfs_peers[ evicted_cnt++ ] = head_idx;
    if( FD_UNLIKELY( evicted_cnt>=256UL ) ) break;
  }
  if( FD_UNLIKELY( evicted_cnt ) ) {
    fd_gui_peers_printf_wfs_remove( peers, peers->scratch.wfs_peers, evicted_cnt );
    fd_http_server_ws_broadcast( peers->http );
    return 1; /* preserve STEM_BURST */
  }

  /* update client viewports in a round-robin */
  if( FD_UNLIKELY( fd_gui_peers_ws_conn_rr_advance( peers, now ) ) ) {
    ulong ws_conn_id = peers->active_ws_conn_id;
    FD_TEST( peers->client_viewports[ ws_conn_id ].connected );
    if( FD_LIKELY( peers->client_viewports[ ws_conn_id ].row_cnt ) ) {
      /* broadcast the diff as cell updates.  fd_http_server_ws_send
         tolerates ws_conn_id having already been closed during
         formatting above. */
      fd_gui_peers_viewport_snap( peers, ws_conn_id );
      fd_gui_printf_peers_viewport_update( peers, ws_conn_id );
      FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );

#if LOGGING
      fd_gui_peers_viewport_log( peers, ws_conn_id );
#endif
      (void)fd_gui_peers_viewport_log;
    }

    /* fd_http_server_ws_send above can close the websocket connection,
       which decrements open_ws_conn_cnt.  If the last client was just
       closed, avoid division by zero and fall back to the base interval. */
    long divisor = fd_long_max( (long)peers->open_ws_conn_cnt, 1L );
    peers->next_client_nanos = now + ((FD_GUI_PEERS_WS_VIEWPORT_UPDATE_INTERVAL_MILLIS * 1000000L) / divisor);
    did_work = 1;
  }

  if( FD_UNLIKELY( now >= peers->next_metric_rate_update_nanos ) ) {
    fd_gui_peers_rate_update( peers, now );
    peers->next_metric_rate_update_nanos = now + (FD_GUI_PEERS_METRIC_RATE_UPDATE_INTERVAL_MILLIS * 1000000L);
    did_work = 1;
#ifdef FD_GUI_USE_HANDHOLDING
    fd_gui_peers_live_table_verify( peers->live_table, peers->contact_info_table );
#endif
  }

  if( FD_LIKELY( now >= peers->next_gossip_stats_update_nanos ) ) {
    fd_gui_peers_gossip_stats_snap( peers, peers->gossip_stats, now );
    fd_gui_peers_printf_gossip_stats( peers );
    fd_http_server_ws_broadcast( peers->http );

    peers->next_gossip_stats_update_nanos = now + (FD_GUI_PEERS_GOSSIP_STATS_UPDATE_INTERVAL_MILLIS * 1000000L);
    return 1; /* preserve STEM_BURST */
  }

  return did_work;
}

void
fd_gui_peers_ws_open( fd_gui_peers_ctx_t *  peers,
                      ulong                 ws_conn_id,
                      long                  now ) {
  peers->client_viewports[ ws_conn_id ].connected = 1;
  peers->client_viewports[ ws_conn_id ].connected_time = now;
  peers->client_viewports[ ws_conn_id ].start_row = 0;
  peers->client_viewports[ ws_conn_id ].row_cnt = 0;
  peers->client_viewports[ ws_conn_id ].sort_key = FD_GUI_PEERS_LIVE_TABLE_DEFAULT_SORT_KEY;
  fd_gui_peers_ws_conn_rr_grow( peers, ws_conn_id );

  fd_gui_peers_printf_node_all( peers );
  FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );

  if( FD_UNLIKELY( peers->wfs_stakes_sent ) ) {
    fd_gui_peers_printf_wfs_stakes( peers );
    FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
  }

  if( FD_UNLIKELY( peers->wfs_peers_valid ) ) {
    ulong added_cnt = 0UL;
    for( ulong i=0UL; i<peers->wfs_peers_cnt; i++ ) {
      if( FD_UNLIKELY( peers->wfs_peers[ i ].is_online ) ) peers->scratch.wfs_peers[ added_cnt++ ] = i;
    }
    if( FD_LIKELY( added_cnt ) ) {
      fd_gui_peers_printf_wfs_add( peers, peers->scratch.wfs_peers, added_cnt );
      FD_TEST( !fd_http_server_ws_send( peers->http, ws_conn_id ) );
    }
  }
}

void
fd_gui_peers_ws_close( fd_gui_peers_ctx_t * peers,
                       ulong                ws_conn_id ) {
  fd_gui_peers_live_table_sort_key_remove( peers->live_table, &peers->client_viewports[ ws_conn_id ].sort_key );
  peers->client_viewports[ ws_conn_id ].connected = 0;
  fd_gui_peers_ws_conn_rr_shrink( peers, ws_conn_id );
}

#undef LOGGING
