#define _GNU_SOURCE /* fd_accdb_idx.h */
#include "topology.h"
#include "../../disco/topo/fd_topob.h"
#include "../../flamenco/progcache/fd_progcache.h"
#include "../../flamenco/accdb/fd_accdb_idx.h"
#include "../../util/pod/fd_pod_format.h"
#include "../shared/fd_action.h"

extern fd_topo_obj_callbacks_t fd_obj_cb_progcache;
extern fd_topo_obj_callbacks_t fd_obj_cb_metrics;
extern fd_topo_obj_callbacks_t fd_obj_cb_tile;
extern fd_topo_obj_callbacks_t fd_obj_cb_accdb_window;

fd_topo_obj_callbacks_t * CALLBACKS[] = {
  &fd_obj_cb_progcache,
  &fd_obj_cb_metrics,
  &fd_obj_cb_tile,
  &fd_obj_cb_accdb_window,
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

static ulong snapin_scratch_sz;
static ulong snapin_scratch_align    ( void )                        { return 4096UL; }
static ulong snapin_scratch_footprint( fd_topo_tile_t const * tile ) { (void)tile; return snapin_scratch_sz; }

static fd_topo_run_tile_t snapin_tile = {
  .name              = "snapin",
  .scratch_align     = snapin_scratch_align,
  .scratch_footprint = snapin_scratch_footprint,
};

fd_topo_run_tile_t * TILES[] = {
  &replay_tile,
  &snapin_tile,
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

  /* A huge page tail replaces a gigantic round-up */
  ulong locked   = fd_topo_wksp_sz( wksp );
  ulong expected = fd_ulong_align_up( wksp_size, wksp->tail_page_cnt ? FD_SHMEM_HUGE_PAGE_SZ : wksp->page_sz );
  if( FD_UNLIKELY( locked!=expected ) ) {
    FD_LOG_ERR(( "wksp_size %lu (%lu MiB): locked %lu B (%lu x %lu B pages + %lu huge), expected %lu B; "
                 "PROGCACHE_WKSP_OVERHEAD_SZ does not cover fd_topob's layout",
                 wksp_size, wksp_size>>20, locked, wksp->page_cnt, wksp->page_sz, wksp->tail_page_cnt, expected ));
  }
}

/* Overlaid tile scratch lands inside the value arena without growing
   the wksp, and falls back to regular space when the arena is full. */

static void
check_overlay( ulong txn_max,
               ulong wksp_size,
               ulong scratch_sz,
               int   fits ) {
  FD_TEST( fd_topob_new( topo, "test" ) );
  fd_topob_wksp( topo, "progcache" );
  fd_topob_wksp( topo, "tile" );
  setup_topo_progcache( topo, "progcache", txn_max, wksp_size );
  ulong obj_id = fd_pod_query_ulong( topo->props, "progcache", ULONG_MAX );
  fd_topo_obj_t * host = &topo->objs[ obj_id ];

  ulong lo, hi;
  FD_TEST( fd_progcache_shmem_arena( txn_max, fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.progcache_sz", obj_id ), &lo, &hi ) );
  FD_TEST( lo<hi && hi<=fd_pod_queryf_ulong( topo->props, 0UL, "obj.%lu.progcache_sz", obj_id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, lo, "obj.%lu.overlay_lo", obj_id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, hi, "obj.%lu.overlay_hi", obj_id ) );

  fd_topo_tile_t * replay = fd_topob_tile( topo, "replay", "tile", "tile", 0UL, 0, 0, 0 );
  fd_topob_tile_uses( topo, replay, host, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_scratch_sz = scratch_sz;
  fd_topo_tile_t * snapin = fd_topob_tile( topo, "snapin", "progcache", "tile", 1UL, 0, 0, 0 );
  fd_topo_obj_t *  so     = &topo->objs[ snapin->tile_obj_id ];
  fd_topob_obj_overlay( topo, so, host );
  fd_topo_obj_t *  win    = fd_topob_obj( topo, "accdb_window", "progcache" );
  fd_topob_obj_overlay( topo, win, host );

  fd_topob_finish( topo, CALLBACKS );

  fd_topo_wksp_t const * wksp = &topo->workspaces[ fd_topo_find_wksp( topo, "progcache" ) ];
  FD_TEST( so->overlay==fits );
  if( fits ) {
    FD_TEST( so->offset>=host->offset+lo && so->offset+so->footprint<=host->offset+hi );
    FD_TEST( wksp->page_cnt*wksp->page_sz==fd_ulong_align_up( wksp_size, wksp->page_sz ) );
  } else {
    FD_TEST( so->offset>=host->offset+host->footprint );
  }
  /* the place window packs after the scratch, disjoint from it */
  FD_TEST( win->overlay && win->footprint==FD_ACCDB_PLACE_WINDOW );
  FD_TEST( win->offset>=host->offset+lo && win->offset+win->footprint<=host->offset+hi );
  FD_TEST( win->offset>=so->offset+so->footprint || so->offset>=win->offset+win->footprint );
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
  check_exact_fit( max_live_slots, setup_topo_progcache_min_sz( max_live_slots )+(3UL<<20) );
  check_exact_fit( max_live_slots,  256UL<<20 );
  check_exact_fit( max_live_slots, 1792UL<<20 );

  /* The advertised minimum provisions, and is itself a huge-page multiple. */
  FD_TEST( fd_ulong_is_aligned( setup_topo_progcache_min_sz( max_live_slots ), FD_SHMEM_HUGE_PAGE_SZ ) );
  check_exact_fit( max_live_slots, setup_topo_progcache_min_sz( max_live_slots ) );
  check_exact_fit(   64UL, setup_topo_progcache_min_sz(   64UL ) );

  check_overlay( max_live_slots, 2UL<<30, 316UL<<20, 1 );
  check_overlay( max_live_slots, 2UL<<30,   3UL<<30, 0 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
