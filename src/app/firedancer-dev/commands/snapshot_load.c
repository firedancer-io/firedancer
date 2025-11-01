#include "../../firedancer/topology.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/restore/utils/fd_ssctrl.h"
#include "../../../discof/restore/utils/fd_ssmsg.h"

#include <sys/resource.h>
#include <linux/capability.h>
#include <unistd.h>
#include <stdio.h>

#include "../../../vinyl/meta/fd_vinyl_meta.h"
#include "../../../discof/restore/fd_snapin_tile_private.h"
#include "../../../flamenco/runtime/fd_hashes.h"

#define NAME "snapshot-load"

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
snapshot_load_topo( config_t * config ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "txncache" );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      fd_ulong_pow2_up( FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib );

  if( config->firedancer.vinyl.enabled ) {
    setup_topo_vinyl( topo, &config->firedancer );
  }

  /* metrics tile *****************************************************/
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", ULONG_MAX, 0, 0 );

  /* read() tile */
  fd_topob_wksp( topo, "snapct" );
  fd_topo_tile_t * snapct_tile = fd_topob_tile( topo, "snapct", "snapct", "metric_in", ULONG_MAX, 0, 0 );
  snapct_tile->allow_shutdown = 1;

  /* load tile */
  fd_topob_wksp( topo, "snapld" );
  fd_topo_tile_t * snapld_tile = fd_topob_tile( topo, "snapld", "snapld", "metric_in", ULONG_MAX, 0, 0 );
  snapld_tile->allow_shutdown = 1;

  /* "snapdc": Zstandard decompress tile */
  fd_topob_wksp( topo, "snapdc" );
  fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", ULONG_MAX, 0, 0 );
  snapdc_tile->allow_shutdown = 1;

  /* "snapin": Snapshot parser tile */
  fd_topob_wksp( topo, "snapin" );
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "snapin", "snapin", "metric_in", ULONG_MAX, 0, 0 );
  snapin_tile->allow_shutdown = 1;

  /* "snapwr": Snapshot writer tile */
  int vinyl_enabled = config->firedancer.vinyl.enabled;
  if( vinyl_enabled ) {
    fd_topob_wksp( topo, "snapwr" );
    fd_topo_tile_t * snapwr_tile = fd_topob_tile( topo, "snapwr", "snapwr", "metric_in", ULONG_MAX, 0, 0 );
    snapwr_tile->allow_shutdown = 1;
  }

  fd_topob_wksp( topo, "snapct_ld"    );
  fd_topob_wksp( topo, "snapld_dc"    );
  fd_topob_wksp( topo, "snapdc_in"    );
  fd_topob_wksp( topo, "snapin_ct"    );
  fd_topob_wksp( topo, "snapin_manif" );
  fd_topob_wksp( topo, "snapct_repr"  );
  if( vinyl_enabled ) fd_topob_wksp( topo, "snapin_wr" );

  fd_topob_link( topo, "snapct_ld",   "snapct_ld",     128UL,   sizeof(fd_ssctrl_init_t),       1UL );
  fd_topob_link( topo, "snapld_dc",   "snapld_dc",     16384UL, USHORT_MAX,                     1UL );
  fd_topob_link( topo, "snapdc_in",   "snapdc_in",     16384UL, USHORT_MAX,                     1UL );
  fd_topob_link( topo, "snapin_ct",   "snapin_ct",     128UL,   0UL,                            1UL );
  fd_topob_link( topo, "snapin_manif", "snapin_manif", 2UL,     sizeof(fd_snapshot_manifest_t), 1UL )->permit_no_consumers = 1;
  fd_topob_link( topo, "snapct_repr", "snapct_repr",   128UL,   0UL,                            1UL )->permit_no_consumers = 1;
  if( vinyl_enabled ) {
    fd_topob_link( topo, "snapin_wr", "snapin_wr", 4UL, 16UL<<20, 1UL );
  }

  fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapin_ct",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_ld",    0UL                                       );
  fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_repr",  0UL                                       );
  fd_topob_tile_in ( topo, "snapld",  0UL, "metric_in", "snapct_ld",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapld",  0UL,              "snapld_dc",    0UL                                       );
  fd_topob_tile_in ( topo, "snapdc",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc",  0UL,              "snapdc_in",    0UL                                       );
  fd_topob_tile_in ( topo, "snapin",  0UL, "metric_in", "snapdc_in",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_ct",    0UL                                       );
  fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_manif", 0UL                                       );
  if( vinyl_enabled ) {
    fd_topob_tile_out( topo, "snapin", 0UL,              "snapin_wr", 0UL );
    fd_topob_tile_in ( topo, "snapwr", 0UL, "metric_in", "snapin_wr", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /* snapin funk / txncache access */
  fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapin_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.funk_obj_id     = funk_obj->id;
  snapin_tile->snapin.txncache_obj_id = txncache_obj->id;
  if( config->firedancer.vinyl.enabled ) {
    ulong vinyl_map_obj_id  = fd_pod_query_ulong( topo->props, "vinyl.meta_map",  ULONG_MAX ); FD_TEST( vinyl_map_obj_id !=ULONG_MAX );
    ulong vinyl_pool_obj_id = fd_pod_query_ulong( topo->props, "vinyl.meta_pool", ULONG_MAX ); FD_TEST( vinyl_pool_obj_id!=ULONG_MAX );

    fd_topo_obj_t * vinyl_map_obj  = &topo->objs[ vinyl_map_obj_id ];
    fd_topo_obj_t * vinyl_pool_obj = &topo->objs[ vinyl_pool_obj_id ];

    fd_topob_tile_uses( topo, snapin_tile, vinyl_map_obj,  FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, snapin_tile, vinyl_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  snapin_tile->snapin.max_live_slots  = config->firedancer.runtime.max_live_slots;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

extern int * fd_log_private_shared_lock;

static void
snapshot_load_args( int *    pargc,
                    char *** pargv,
                    args_t * args ) {
  (void)pargc; (void)pargv; (void)args;
}

static void
snapshot_load_cmd_fn( args_t *   args,
                      config_t * config ) {
  (void)args;
  if( FD_UNLIKELY( config->firedancer.snapshots.sources.gossip.allow_any || 0UL!=config->firedancer.snapshots.sources.gossip.allow_list_cnt ) ) {
    FD_LOG_ERR(( "snapshot-load command is incompatible with gossip snapshot sources" ));
  }
  fd_topo_t * topo = &config->topo;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  for( ulong i=0UL; STAGES[ i ]; i++ )
    configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_fn( &configure_args, config );

  run_firedancer_init( config, 1, 0 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( topo );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;

  long start = fd_log_wallclock();
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  fd_topo_tile_t * snapct_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapct", 0UL ) ];
  fd_topo_tile_t * snapld_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapld", 0UL ) ];
  fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", 0UL ) ];
  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];
  ulong            snapwr_idx  =               fd_topo_find_tile( topo, "snapwr", 0UL );
  fd_topo_tile_t * snapwr_tile = snapwr_idx!=ULONG_MAX ? &topo->tiles[ snapwr_idx ] : NULL;

  ulong volatile * const snapct_metrics = fd_metrics_tile( snapct_tile->metrics );
  ulong volatile * const snapld_metrics = fd_metrics_tile( snapld_tile->metrics );
  ulong volatile * const snapdc_metrics = fd_metrics_tile( snapdc_tile->metrics );
  ulong volatile * const snapin_metrics = fd_metrics_tile( snapin_tile->metrics );
  ulong volatile * const snapwr_metrics = snapwr_tile ? fd_metrics_tile( snapwr_tile->metrics ) : NULL;

  ulong total_off_old    = 0UL;
  ulong decomp_off_old   = 0UL;
  ulong vinyl_off_old    = 0UL;
  ulong snapct_backp_old = 0UL;
  ulong snapct_wait_old  = 0UL;
  ulong snapld_backp_old = 0UL;
  ulong snapld_wait_old  = 0UL;
  ulong snapdc_backp_old = 0UL;
  ulong snapdc_wait_old  = 0UL;
  ulong snapin_backp_old = 0UL;
  ulong snapin_wait_old  = 0UL;
  ulong snapwr_wait_old  = 0UL;
  ulong acc_cnt_old      = 0UL;
  sleep( 1 );
  puts( "" );
  puts( "Columns:" );
  puts( "- comp:  Compressed bandwidth"             );
  puts( "- raw:   Uncompressed bandwidth"           );
  puts( "- backp: Backpressured by downstream tile" );
  puts( "- stall: Waiting on upstream tile"         );
  puts( "- acc:   Number of accounts"               );
  puts( "" );
  fputs( "--------------------------------------------", stdout );
  if( snapwr_tile ) fputs( "--------------", stdout );
  fputs( "[ct],[ld],[dc],[in]--------[ct],[ld],[dc],[in]", stdout );
  if( snapwr_tile ) fputs( ",[wr]" , stdout );
  puts( "--------------" );
  long next = start+1000L*1000L*1000L;
  for(;;) {
    ulong snapct_status = FD_VOLATILE_CONST( snapct_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapld_status = FD_VOLATILE_CONST( snapld_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = FD_VOLATILE_CONST( snapdc_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snapin_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );

    if( FD_UNLIKELY( snapct_status==2UL && snapld_status==2UL && snapdc_status==2UL && snapin_status == 2UL ) ) break;

    long cur = fd_log_wallclock();
    if( FD_UNLIKELY( cur<next ) ) {
      long sleep_nanos = fd_long_min( 1000L*1000L, next-cur );
      FD_TEST( !fd_sys_util_nanosleep(  (uint)(sleep_nanos/(1000L*1000L*1000L)), (uint)(sleep_nanos%(1000L*1000L*1000L)) ) );
      continue;
    }

    ulong total_off    = snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ] +
                         snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_READ ) ];
    ulong decomp_off   = snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_READ ) ] +
                         snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_READ ) ];
    ulong vinyl_off    = snapwr_tile ? snapwr_metrics[ MIDX( GAUGE, SNAPWR, VINYL_BYTES_WRITTEN ) ] : 0UL;
    ulong snapct_backp = snapct_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapct_wait  = snapct_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapct_backp;
    ulong snapld_backp = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapld_wait  = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapld_backp;
    ulong snapdc_backp = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapdc_wait  = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapdc_backp;
    ulong snapin_backp = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapin_wait  = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapin_backp;
    ulong snapwr_wait  = 0UL;
    if( snapwr_tile ) {
      snapwr_wait      = snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] +
                         snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    }

    double progress = 100.0 * (double)snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ] / (double)snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_TOTAL ) ];

    ulong acc_cnt      = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED    ) ];
    printf( "%5.1f %% comp=%4.0fMB/s snap=%4.0fMB/s",
            progress,
            (double)( total_off -total_off_old  )/1e6,
            (double)( decomp_off-decomp_off_old )/1e6 );
    if( snapwr_tile ) {
      printf( " vinyl=%4.0fMB/s", (double)( vinyl_off - vinyl_off_old )/1e6 );
    }
    printf( " backp=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%",
            ( (double)( snapct_backp-snapct_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapld_backp-snapld_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapdc_backp-snapdc_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapin_backp-snapin_backp_old )*ns_per_tick )/1e7 );
    printf( ") busy=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%",
            100-( ( (double)( snapct_wait-snapct_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapld_wait-snapld_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapdc_wait-snapdc_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapin_wait-snapin_wait_old  )*ns_per_tick )/1e7 ) );
    if( snapwr_tile ) {
      printf( ",%3.0f%%",
            100-( ( (double)( snapwr_wait-snapwr_wait_old  )*ns_per_tick )/1e7 ) );
    }
    printf( ") acc=%4.1f M/s\n",
            (double)( acc_cnt-acc_cnt_old  )/1e6 );
    fflush( stdout );
    total_off_old    = total_off;
    decomp_off_old   = decomp_off;
    vinyl_off_old    = vinyl_off;
    snapct_backp_old = snapct_backp;
    snapct_wait_old  = snapct_wait;
    snapld_backp_old = snapld_backp;
    snapld_wait_old  = snapld_wait;
    snapdc_backp_old = snapdc_backp;
    snapdc_wait_old  = snapdc_wait;
    snapin_backp_old = snapin_backp;
    snapin_wait_old  = snapin_wait;
    snapwr_wait_old  = snapwr_wait;
    acc_cnt_old      = acc_cnt;

    next+=1000L*1000L*1000L;
  }
  puts( "snapshot load done" );

  /* verification (work-in-progress) */
  if( 1 ) {
    void * scratch = fd_topo_obj_laddr( topo, snapin_tile->tile_obj_id );
    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_snapin_tile_t * ctx  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );

    fd_lthash_value_t lthash_sum[1];
    fd_lthash_zero( lthash_sum );

    ulong cnt=0UL;
    ulong pairs_cnt = 0UL;

    if( ctx->use_vinyl ) {
      /* vinyl version */
      FD_LOG_NOTICE(( "VINYL" ));
      ulong vinyl_map_ele_max   = fd_vinyl_meta_ele_max  ( ctx->vinyl.map );

      for( ulong ele_i=0; ele_i < vinyl_map_ele_max; ele_i++ ) {
        fd_vinyl_meta_ele_t const * ele = ctx->vinyl.map->ele + ele_i;

        if( FD_UNLIKELY( fd_vinyl_meta_private_ele_is_free( ctx->vinyl.map->ctx, ele ) ) ) continue;

        cnt++;

        fd_vinyl_bstream_phdr_t _phdr      = ele->phdr;
        ulong                   _seq       = ele->seq;
        FD_TEST( !!_phdr.ctl );

        fd_vinyl_bstream_block_t * block = (void *)( ctx->vinyl.bstream_mem + _seq );
        ulong                   ctl  = FD_VOLATILE_CONST( block->ctl  );
        fd_vinyl_bstream_phdr_t phdr = FD_VOLATILE_CONST( block->phdr );
        int   block_type = fd_vinyl_bstream_ctl_type( ctl );

        if( FD_LIKELY( block_type==FD_VINYL_BSTREAM_CTL_TYPE_PAIR ) ) {

          uchar * pair = (uchar*)block;
          pair += sizeof(fd_vinyl_bstream_phdr_t);
          fd_account_meta_t * meta = (fd_account_meta_t *)pair;
          pair += sizeof(fd_account_meta_t);
          uchar * data = pair;

          fd_lthash_value_t new_hash[1];
          fd_pubkey_t * account_pubkey = (fd_pubkey_t*)phdr.key.c;
          fd_hashes_account_lthash( account_pubkey, meta, data, new_hash );
          fd_lthash_add( lthash_sum, new_hash );
          // FD_LOG_NOTICE(( "account_pubkey %32s  lthash %32s  lthash_sum %32s", FD_BASE58_ENC_32_ALLOCA( account_pubkey ), FD_LTHASH_ENC_32_ALLOCA( new_hash->bytes ), FD_LTHASH_ENC_32_ALLOCA( lthash_sum ) ));

          pairs_cnt++;
        }
      }
    }
    else {
      /* funk version */
      FD_LOG_NOTICE(( "FUNK" ));

      fd_funk_t * funk = ctx->accdb->funk;
      fd_funk_rec_map_t  const * rec_map = funk->rec_map;
      fd_funk_rec_t const * ele = rec_map->ele;

      fd_funk_rec_map_shmem_private_chain_t const * chain = fd_funk_rec_map_shmem_private_chain_const( rec_map->map, 0UL );
      ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
      for( ulong chain_i=0UL; chain_i < chain_cnt; chain_i++ ) {

        ulong ver_cnt = chain[ chain_i ].ver_cnt;
        ulong ele_cnt = fd_funk_rec_map_private_vcnt_cnt( ver_cnt );

        ulong head_i = fd_funk_rec_map_private_idx( chain[ chain_i ].head_cidx );
        ulong ele_i = head_i;

        for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) {
          cnt++;

          fd_funk_xid_key_pair_t const * pair = &ele[ ele_i ].pair;
          fd_pubkey_t * account_pubkey = (fd_pubkey_t*)pair->key->uc;

          fd_funk_rec_query_t query[1];
          fd_funk_rec_t * rec = fd_funk_rec_query_try( funk, pair->xid, pair->key, query );
          FD_TEST( !!rec );

          fd_account_meta_t * meta = fd_funk_val( rec, funk->wksp );
          FD_TEST( !!meta );

          uchar * data = ((uchar*)meta) + sizeof(fd_account_meta_t);

          fd_lthash_value_t new_hash[1];
          fd_hashes_account_lthash( account_pubkey, meta, data, new_hash );
          fd_lthash_add( lthash_sum, new_hash );
          // FD_LOG_NOTICE(( "account_pubkey %32s  lthash %32s  lthash_sum %32s", FD_BASE58_ENC_32_ALLOCA( account_pubkey ), FD_LTHASH_ENC_32_ALLOCA( new_hash->bytes ), FD_LTHASH_ENC_32_ALLOCA( lthash_sum ) ));

          pairs_cnt++;
        }
      }
    }

    /* summary stats */
    FD_LOG_NOTICE(( "... cnt %lu", cnt ));
    FD_LOG_NOTICE(( "... pairs_cnt %lu", pairs_cnt ));
    FD_LOG_NOTICE(( "... lthash_sum %32s", FD_LTHASH_ENC_32_ALLOCA( lthash_sum ) ));
  }
}

action_t fd_action_snapshot_load = {
  .name = NAME,
  .args = snapshot_load_args,
  .topo = snapshot_load_topo,
  .perm = dev_cmd_perm,
  .fn   = snapshot_load_cmd_fn
};
