#include "topology.h"
#include "../../disco/topo/fd_topob.h"
#include "../../flamenco/progcache/fd_progcache.h"
#include "../../util/pod/fd_pod.h"
#include "../shared/fd_action.h"

extern fd_topo_obj_callbacks_t fd_obj_cb_progcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_progcache,
  &fd_obj_cb_metrics,
  &fd_obj_cb_tile,
  NULL,
};

/* topology.c resolves tile names through TILES; nothing here is run. */

static ulong replay_scratch_align    ( void )                        { return 128UL;  }
static ulong replay_scratch_footprint( fd_topo_tile_t const * tile ) { (void)tile; return 4096UL; }

static fd_topo_run_tile_t replay_tile = {
  .name              = "replay",
  .scratch_align     = replay_scratch_align,
  .scratch_footprint = replay_scratch_footprint,
};

fd_topo_run_tile_t * TILES[] = {
  &replay_tile,
  NULL,
};

/* Referenced by fdctl_shared's help/action machinery, unused here. */

char const * FD_APP_NAME    = "Firedancer";
char const * FD_BINARY_NAME = "firedancer";

action_t * ACTIONS[] = {
  NULL,
};

static fd_topo_t topo[1];

static void
check_exact_fit( ulong txn_max,
                 ulong wksp_size ) {
  FD_TEST( fd_topob_new( topo, "test" ) );
  fd_topob_wksp( topo, "progcache" );
  fd_topob_wksp( topo, "tile" );
  setup_topo_progcache( topo, "progcache", txn_max, wksp_size );

  /* The progcache wksp must hold nothing but the cache, so the tile that
     claims it lives elsewhere. */
  fd_topo_tile_t * tile = fd_topob_tile( topo, "replay", "tile", "tile", 0UL, 0, 0, 0 );
  ulong obj_id = fd_pod_query_ulong( topo->props, "progcache", ULONG_MAX );
  FD_TEST( obj_id!=ULONG_MAX );
  fd_topob_tile_uses( topo, tile, &topo->objs[ obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_finish( topo, CALLBACKS );

  ulong wksp_idx = fd_topo_find_wksp( topo, "progcache" );
  FD_TEST( wksp_idx!=ULONG_MAX );
  fd_topo_wksp_t const * wksp = &topo->workspaces[ wksp_idx ];

  ulong locked = wksp->page_cnt*wksp->page_sz;
  if( FD_UNLIKELY( locked!=fd_ulong_align_up( wksp_size, wksp->page_sz ) ) ) {
    FD_LOG_ERR(( "wksp_size %lu (%lu MiB): locked %lu B (%lu x %lu B pages), expected %lu B; "
                 "wksp_overhead_sz no longer covers fd_topob's layout",
                 wksp_size, wksp_size>>20, locked, wksp->page_cnt, wksp->page_sz,
                 fd_ulong_align_up( wksp_size, wksp->page_sz ) ));
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  const ulong max_live_slots = 2048UL;

  /* Gigantic-page multiples: an off-by-one page wastes a whole GiB. */
  check_exact_fit( max_live_slots, 1UL<<30 );
  check_exact_fit( max_live_slots, 2UL<<30 );
  check_exact_fit( max_live_slots, 4UL<<30 );

  /* Non-multiples round up to the page size and no further. */
  check_exact_fit( max_live_slots,  143UL<<20 );
  check_exact_fit( max_live_slots,  256UL<<20 );
  check_exact_fit( max_live_slots, 1792UL<<20 );

  /* The advertised minimum provisions. */
  check_exact_fit( max_live_slots, fd_progcache_shmem_min_sz( max_live_slots ) );
  check_exact_fit(   64UL, fd_progcache_shmem_min_sz(   64UL ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
