/* test_topob.c – unit tests for fd_topob_auto_layout_cpus.

   Tests verify the auto-layout algorithm on synthetic CPU topologies
   for various core counts, tile sets, and blocklists.

   Each test supplies:
     - a synthetic CPU topology  (physical cores × 2 with HT siblings)
     - a tile set                (tile names and counts)
     - a blocklist               (core indices to exclude)
     - reserve_agave flag        (1 for Frankendancer, 0 for Firedancer)
     - an expected per-CPU array:
         expected[cpu] = tile name   →  tile assigned to that cpu
         expected[cpu] = _A_         →  cpu reserved for Agave
         expected[cpu] = NULL (__) →  cpu unassigned                   */

#include "fd_topob.h"
#include "fd_cpu_topo.h"

/* ---- Tile specification ------------------------------------------------ */

typedef struct { char const * name; ulong cnt; } tile_spec_t;

/* ---- Helpers ----------------------------------------------------------- */

/* Create a synthetic HT CPU topology.
   physical_cores physical cores on a single NUMA node.
   Core i has HT sibling at physical_cores+i.
   Total logical CPUs = 2 * physical_cores. */
static void
make_cpus( fd_topo_cpus_t * cpus,
           ulong            physical_cores ) {
  fd_memset( cpus, 0, sizeof(*cpus) );
  cpus->numa_node_cnt = 1UL;
  cpus->cpu_cnt       = 2UL * physical_cores;
  for( ulong i=0UL; i<physical_cores; i++ ) {
    cpus->cpu[ i ].idx       = i;
    cpus->cpu[ i ].online    = 1;
    cpus->cpu[ i ].numa_node = 0UL;
    cpus->cpu[ i ].sibling   = physical_cores + i;
  }
  for( ulong i=0UL; i<physical_cores; i++ ) {
    ulong s = physical_cores + i;
    cpus->cpu[ s ].idx       = s;
    cpus->cpu[ s ].online    = 1;
    cpus->cpu[ s ].numa_node = 0UL;
    cpus->cpu[ s ].sibling   = i;
  }
}

/* Add tiles to the topology from a NULL-terminated spec array.
   Only sets fields used by the layout algorithm. */
static void
make_tiles( fd_topo_t *         topo,
            tile_spec_t const * specs ) {
  topo->tile_cnt = 0UL;
  for( tile_spec_t const * s = specs; s->name; s++ ) {
    for( ulong i=0UL; i<s->cnt; i++ ) {
      FD_TEST( topo->tile_cnt < FD_TOPO_MAX_TILES );
      fd_topo_tile_t * tile = &topo->tiles[ topo->tile_cnt ];
      fd_memset( tile, 0, sizeof(*tile) );
      strncpy( tile->name, s->name, sizeof(tile->name) );
      tile->id      = topo->tile_cnt;
      tile->cpu_idx = ULONG_MAX;

      /* Compute kind_id = count of prior tiles with same name */
      ulong kind_id = 0UL;
      for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
        if( !strcmp( topo->tiles[ j ].name, s->name ) ) kind_id++;
      }
      tile->kind_id = kind_id;
      topo->tile_cnt++;
    }
  }
}

/* Set the blocklist on the topology.
   blocklist[] is terminated by ULONG_MAX. */
static void
set_blocklist( fd_topo_t *   topo,
               ulong const * blocklist ) {
  topo->blocklist_cores_cnt = 0UL;
  for( ulong const * p = blocklist; *p != ULONG_MAX; p++ ) {
    topo->blocklist_cores_cpu_idx[ topo->blocklist_cores_cnt++ ] = *p;
  }
}

/* Build the per-CPU → label map from the layout result.
   Tiles get their tile name, agave cores get "AGAVE", rest NULL. */
static void
build_cpu_map( fd_topo_t const * topo,
               ulong             cpu_cnt,
               char const **     out ) {
  for( ulong i=0UL; i<cpu_cnt; i++ ) out[ i ] = NULL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ulong c = topo->tiles[ i ].cpu_idx;
    if( c != ULONG_MAX && c < cpu_cnt ) out[ c ] = topo->tiles[ i ].name;
  }
  for( ulong i=0UL; i<topo->agave_affinity_cnt; i++ ) {
    ulong c = topo->agave_affinity_cpu_idx[ i ];
    if( c < cpu_cnt ) out[ c ] = "AGAVE";
  }
}

/* Print the actual layout for debugging / generating expected arrays. */
static void
print_layout( fd_topo_t const * topo,
              ulong             cpu_cnt ) {
  char const * map[ 1024 ];
  FD_TEST( cpu_cnt <= 1024UL );
  build_cpu_map( topo, cpu_cnt, map );
  for( ulong i=0UL; i<cpu_cnt; i++ ) {
    FD_LOG_NOTICE(( "  /* %3lu */ %s,", i, map[ i ] ? map[ i ] : "NULL" ));
  }
}

/* ---- Test runner ------------------------------------------------------- */

/* Verify the layout of tiles and agave cores matches expected[].
   expected[i] = tile name  →  tile should be assigned to cpu i
   expected[i] = "AGAVE"  →  cpu should be in agave affinity set
   expected[i] = NULL       →  cpu unassigned (blocked / unused)
   Entries beyond expected_len must also be unassigned. */
static void
run_test( char const *          test_name,
          ulong                 physical_cores,
          tile_spec_t const *   tiles,
          ulong const *         blocklist,      /* ULONG_MAX terminated */
          int                   reserve_agave,
          ulong                 expected_len,
          char const * const *  expected ) {

  FD_LOG_NOTICE(( "=== %s (%lu phys × 2) ===", test_name, physical_cores ));

  /* Build CPU topology */
  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, physical_cores );
  ulong cpu_cnt = cpus->cpu_cnt;

  /* Build tile topology */
  static fd_topo_t _topo[1];   /* static – too large for stack */
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, tiles );
  set_blocklist( topo, blocklist );

  /* Run the layout algorithm */
  fd_topob_auto_layout_cpus( topo, cpus, reserve_agave );

  /* Build actual per-CPU map (tiles + agave) */
  char const * actual[ 1024 ];
  FD_TEST( cpu_cnt <= 1024UL );
  build_cpu_map( topo, cpu_cnt, actual );

  /* Compare against expected */
  int ok = 1;
  for( ulong i=0UL; i<cpu_cnt; i++ ) {
    char const * exp = (i < expected_len) ? expected[ i ] : NULL;
    char const * act = actual[ i ];
    int match;
    if( !exp && !act )      match = 1;
    else if( !exp || !act ) match = 0;
    else                    match = !strcmp( exp, act );
    if( !match ) {
      FD_LOG_WARNING(( "  cpu %3lu: expected %-8s got %-8s  MISMATCH",
                        i, exp ? exp : "NULL", act ? act : "NULL" ));
      ok = 0;
    }
  }
  if( !ok ) {
    FD_LOG_WARNING(( "  Full actual layout:" ));
    print_layout( topo, cpu_cnt );
  }
  FD_TEST( ok );
  FD_LOG_NOTICE(( "  PASS" ));
}

/* ======================================================================== */
/*  Tile definitions                                                        */
/* ======================================================================== */

/* --- Firedancer default (no snapshots, no rpc, no telemetry, no vinyl) -- */

static tile_spec_t const FIREDANCER_TILES[] = {
  /* floating tiles */
  { "netlnk", 1 },
  { "metric", 1 }, { "diag",   1 }, { "genesi", 1 }, { "ipecho", 1 },
  /* ordered tiles (36) */
  { "net",    2 }, { "quic",   1 }, { "verify", 6 }, { "dedup",  1 },
  { "resolv", 1 }, { "pack",   1 }, { "execle", 2 }, { "poh",    1 },
  { "shred",  1 }, { "sign",   2 }, { "gui",    1 }, { "gossvf", 2 },
  { "gossip", 1 }, { "repair", 1 }, { "replay", 1 }, { "execrp",10 },
  { "txsend", 1 }, { "tower",  1 },
  { NULL, 0 }
};

/* --- Frankendancer default (from default.toml) ---------------------------
   net=1, quic=1, verify=6, resolh=1, bank=4, shred=1
   Fixed: dedup=1, pack=1, pohh=1, store=1, sign=1, plugin=1, gui=1
   Total ordered tiles: 21                                               */

static tile_spec_t const FRANKENDANCER_TILES[] = {
  /* floating tiles */
  { "netlnk", 1 },
  { "metric", 1 }, { "diag",   1 },
  /* ordered tiles (21) */
  { "net",    1 }, { "quic",   1 }, { "verify", 6 }, { "dedup",  1 },
  { "resolh", 1 }, { "pack",   1 }, { "bank",   4 }, { "pohh",   1 },
  { "shred",  1 }, { "store",  1 }, { "sign",   1 }, { "plugin", 1 },
  { "gui",    1 },
  { NULL, 0 }
};

/* ======================================================================== */
/*  Blocklists                                                              */
/* ======================================================================== */

/* Default "0h" blocklist for N physical cores:
   cores 0 and N are blocked.  Built per-test as a local array. */

#define BLOCKLIST_0H( N ) { 0, (N), ULONG_MAX }

/* ======================================================================== */
/*  Expected results                                                        */
/*                                                                          */
/*  For each test, expected[cpu] = tile name, _A_ (Agave), or __ (unused). */
/* ======================================================================== */

#define __ NULL
#define _A_ "AGAVE"

/* ---- Firedancer, skip-HT expected prefix (48/64/128 physical) ----------
   When enough physical cores, tiles occupy consecutive cores 1..36.
   HT siblings are all unassigned.                                         */

static char const * const FD_SKIP_HT[] = {
  /* phys cores 0-36 */
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "net",     /*  3 */ "quic",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "verify",  /*  7 */ "verify",
  /*  8 */ "verify",  /*  9 */ "verify",  /* 10 */ "dedup",   /* 11 */ "resolv",
  /* 12 */ "pack",    /* 13 */ "execle",  /* 14 */ "execle",  /* 15 */ "poh",
  /* 16 */ "shred",   /* 17 */ "sign",    /* 18 */ "sign",    /* 19 */ "gui",
  /* 20 */ "gossvf",  /* 21 */ "gossvf",  /* 22 */ "gossip",  /* 23 */ "repair",
  /* 24 */ "replay",  /* 25 */ "execrp",  /* 26 */ "execrp",  /* 27 */ "execrp",
  /* 28 */ "execrp",  /* 29 */ "execrp",  /* 30 */ "execrp",  /* 31 */ "execrp",
  /* 32 */ "execrp",  /* 33 */ "execrp",  /* 34 */ "execrp",  /* 35 */ "txsend",
  /* 36 */ "tower",
};
#define FD_SKIP_HT_LEN (sizeof(FD_SKIP_HT)/sizeof(FD_SKIP_HT[0]))

/* ---- Frankendancer, skip-HT tile prefix (shared by 48/64/128) ----------
   Tiles on physical cores 1-21, core 0 blocked.
   Order follows ORDERED array: net, quic, verify(×6), dedup, resolh, pack,
   bank(×4), pohh, shred, store, sign, plugin, gui.
   Used as prefix; each test adds _A_ for the agave region.               */

static char const * const FRANK_SKIP_HT_PREFIX[] = {
  /* phys cores 0-21 */
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "quic",    /*  3 */ "verify",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "verify",  /*  7 */ "verify",
  /*  8 */ "verify",  /*  9 */ "dedup",   /* 10 */ "resolh",  /* 11 */ "pack",
  /* 12 */ "bank",    /* 13 */ "bank",    /* 14 */ "bank",    /* 15 */ "bank",
  /* 16 */ "pohh",    /* 17 */ "shred",   /* 18 */ "store",   /* 19 */ "sign",
  /* 20 */ "plugin",  /* 21 */ "gui",
};
#define FRANK_SKIP_HT_PREFIX_LEN (sizeof(FRANK_SKIP_HT_PREFIX)/sizeof(FRANK_SKIP_HT_PREFIX[0]))

/* ---- Firedancer 24×2  (no skip HT, 36 tiles > 23 physical cores) ------ */

static char const * const FD_24X2[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "quic",    /*  3 */ "verify",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "resolv",  /*  7 */ "pack",
  /*  8 */ "execle",  /*  9 */ "poh",     /* 10 */ "sign",    /* 11 */ "gui",
  /* 12 */ "gossvf",  /* 13 */ "gossip",  /* 14 */ "replay",  /* 15 */ "execrp",
  /* 16 */ "execrp",  /* 17 */ "execrp",  /* 18 */ "execrp",  /* 19 */ "execrp",
  /* 20 */ "tower",   /* 21 */ __,        /* 22 */ __,        /* 23 */ __,
  /* --- HT siblings (24-47) --- */
  /* 24 */ __,        /* 25 */ "net",     /* 26 */ "verify",  /* 27 */ "verify",
  /* 28 */ "verify",  /* 29 */ "dedup",   /* 30 */ "execle",  /* 31 */ __,
  /* 32 */ "shred",   /* 33 */ __,        /* 34 */ "sign",    /* 35 */ __,
  /* 36 */ "gossvf",  /* 37 */ "repair",  /* 38 */ "execrp",  /* 39 */ "execrp",
  /* 40 */ "execrp",  /* 41 */ "execrp",  /* 42 */ "execrp",  /* 43 */ "txsend",
  /* 44 */ __,        /* 45 */ __,        /* 46 */ __,        /* 47 */ __,
};
#define FD_24X2_LEN (sizeof(FD_24X2)/sizeof(FD_24X2[0]))

/* ---- Firedancer 32×2  (no skip HT, 36 tiles > 31 physical cores) ------ */

static char const * const FD_32X2[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "quic",    /*  3 */ "verify",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "resolv",  /*  7 */ "pack",
  /*  8 */ "execle",  /*  9 */ "poh",     /* 10 */ "sign",    /* 11 */ "gui",
  /* 12 */ "gossvf",  /* 13 */ "gossip",  /* 14 */ "replay",  /* 15 */ "execrp",
  /* 16 */ "execrp",  /* 17 */ "execrp",  /* 18 */ "execrp",  /* 19 */ "execrp",
  /* 20 */ "tower",   /* 21 */ __,        /* 22 */ __,        /* 23 */ __,
  /* 24 */ __,        /* 25 */ __,        /* 26 */ __,        /* 27 */ __,
  /* 28 */ __,        /* 29 */ __,        /* 30 */ __,        /* 31 */ __,
  /* --- HT siblings (32-63) --- */
  /* 32 */ __,        /* 33 */ "net",     /* 34 */ "verify",  /* 35 */ "verify",
  /* 36 */ "verify",  /* 37 */ "dedup",   /* 38 */ "execle",  /* 39 */ __,
  /* 40 */ "shred",   /* 41 */ __,        /* 42 */ "sign",    /* 43 */ __,
  /* 44 */ "gossvf",  /* 45 */ "repair",  /* 46 */ "execrp",  /* 47 */ "execrp",
  /* 48 */ "execrp",  /* 49 */ "execrp",  /* 50 */ "execrp",  /* 51 */ "txsend",
  /* 52 */ __,        /* 53 */ __,        /* 54 */ __,        /* 55 */ __,
  /* 56 */ __,        /* 57 */ __,        /* 58 */ __,        /* 59 */ __,
  /* 60 */ __,        /* 61 */ __,        /* 62 */ __,        /* 63 */ __,
};
#define FD_32X2_LEN (sizeof(FD_32X2)/sizeof(FD_32X2[0]))

/* ---- Frankendancer 24×2  (no skip HT, 21 ordered tiles from default.toml)
   Tiles on physical 1-12 and HT 25-29,31-32,34-35.
   Critical siblings blocked: 30(pack),33(pohh),36(gui).
   Agave: physical 13-23, HT 37-47.                                       */

static char const * const FRANK_24X2[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "verify",  /*  3 */ "verify",
  /*  4 */ "verify",  /*  5 */ "dedup",   /*  6 */ "pack",    /*  7 */ "bank",
  /*  8 */ "bank",    /*  9 */ "pohh",    /* 10 */ "shred",   /* 11 */ "sign",
  /* 12 */ "gui",     /* 13 */ _A_,       /* 14 */ _A_,       /* 15 */ _A_,
  /* 16 */ _A_,       /* 17 */ _A_,       /* 18 */ _A_,       /* 19 */ _A_,
  /* 20 */ _A_,       /* 21 */ _A_,       /* 22 */ _A_,       /* 23 */ _A_,
  /* --- HT siblings (24-47) --- */
  /* 24 */ __,        /* 25 */ "quic",    /* 26 */ "verify",  /* 27 */ "verify",
  /* 28 */ "verify",  /* 29 */ "resolh",  /* 30 */ __,        /* 31 */ "bank",
  /* 32 */ "bank",    /* 33 */ __,        /* 34 */ "store",   /* 35 */ "plugin",
  /* 36 */ __,        /* 37 */ _A_,       /* 38 */ _A_,       /* 39 */ _A_,
  /* 40 */ _A_,       /* 41 */ _A_,       /* 42 */ _A_,       /* 43 */ _A_,
  /* 44 */ _A_,       /* 45 */ _A_,       /* 46 */ _A_,       /* 47 */ _A_,
};
#define FRANK_24X2_LEN (sizeof(FRANK_24X2)/sizeof(FRANK_24X2[0]))

/* ---- Frankendancer 32×2  (no skip HT, 21 ordered tiles from default.toml)
   Tiles on physical 1-12 and HT 33-37,39-40,42-43.
   Critical siblings blocked: 38(pack),41(pohh),44(gui).
   Agave: physical 13-31, HT 45-63.                                       */

static char const * const FRANK_32X2[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "verify",  /*  3 */ "verify",
  /*  4 */ "verify",  /*  5 */ "dedup",   /*  6 */ "pack",    /*  7 */ "bank",
  /*  8 */ "bank",    /*  9 */ "pohh",    /* 10 */ "shred",   /* 11 */ "sign",
  /* 12 */ "gui",     /* 13 */ _A_,       /* 14 */ _A_,       /* 15 */ _A_,
  /* 16 */ _A_,       /* 17 */ _A_,       /* 18 */ _A_,       /* 19 */ _A_,
  /* 20 */ _A_,       /* 21 */ _A_,       /* 22 */ _A_,       /* 23 */ _A_,
  /* 24 */ _A_,       /* 25 */ _A_,       /* 26 */ _A_,       /* 27 */ _A_,
  /* 28 */ _A_,       /* 29 */ _A_,       /* 30 */ _A_,       /* 31 */ _A_,
  /* --- HT siblings (32-63) --- */
  /* 32 */ __,        /* 33 */ "quic",    /* 34 */ "verify",  /* 35 */ "verify",
  /* 36 */ "verify",  /* 37 */ "resolh",  /* 38 */ __,        /* 39 */ "bank",
  /* 40 */ "bank",    /* 41 */ __,        /* 42 */ "store",   /* 43 */ "plugin",
  /* 44 */ __,        /* 45 */ _A_,       /* 46 */ _A_,       /* 47 */ _A_,
  /* 48 */ _A_,       /* 49 */ _A_,       /* 50 */ _A_,       /* 51 */ _A_,
  /* 52 */ _A_,       /* 53 */ _A_,       /* 54 */ _A_,       /* 55 */ _A_,
  /* 56 */ _A_,       /* 57 */ _A_,       /* 58 */ _A_,       /* 59 */ _A_,
  /* 60 */ _A_,       /* 61 */ _A_,       /* 62 */ _A_,       /* 63 */ _A_,
};
#define FRANK_32X2_LEN (sizeof(FRANK_32X2)/sizeof(FRANK_32X2[0]))

/* ---- Variation: Firedancer 32×2, fewer tiles → skip HT -----------------
   verify=2, execrp=4  →  26 tiles total, 31 available ≥ 26              */

static tile_spec_t const FD_FEWER_TILES[] = {
  { "netlnk", 1 },
  { "metric", 1 }, { "diag",   1 }, { "genesi", 1 }, { "ipecho", 1 },
  { "net",    2 }, { "quic",   1 }, { "verify", 2 }, { "dedup",  1 },
  { "resolv", 1 }, { "pack",   1 }, { "execle", 2 }, { "poh",    1 },
  { "shred",  1 }, { "sign",   2 }, { "gui",    1 }, { "gossvf", 2 },
  { "gossip", 1 }, { "repair", 1 }, { "replay", 1 }, { "execrp", 4 },
  { "txsend", 1 }, { "tower",  1 },
  { NULL, 0 }
};

static char const * const FD_32X2_FEWER[] = {
  /* skip_ht: sequential assignment on physical cores 1..26 */
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "net",     /*  3 */ "quic",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "dedup",   /*  7 */ "resolv",
  /*  8 */ "pack",    /*  9 */ "execle",  /* 10 */ "execle",  /* 11 */ "poh",
  /* 12 */ "shred",   /* 13 */ "sign",    /* 14 */ "sign",    /* 15 */ "gui",
  /* 16 */ "gossvf",  /* 17 */ "gossvf",  /* 18 */ "gossip",  /* 19 */ "repair",
  /* 20 */ "replay",  /* 21 */ "execrp",  /* 22 */ "execrp",  /* 23 */ "execrp",
  /* 24 */ "execrp",  /* 25 */ "txsend",  /* 26 */ "tower",
};
#define FD_32X2_FEWER_LEN (sizeof(FD_32X2_FEWER)/sizeof(FD_32X2_FEWER[0]))

/* ---- Variation: Frankendancer 32×2, more bank tiles → still no skip HT --
   bank=4, verify=6  →  23 ordered tiles, 2×23=46 > 31
   Tiles on physical 1-13 and HT 33-38,40-41,43-44.
   Critical siblings blocked: 39(pack),42(pohh),45(gui).
   Agave: physical 14-31, HT 46-63.                                       */

static tile_spec_t const FRANK_MORE_BANK[] = {
  { "netlnk", 1 },
  { "metric", 1 }, { "diag",   1 },
  { "net",    2 }, { "quic",   1 }, { "verify", 6 }, { "dedup",  1 },
  { "resolh", 1 }, { "pack",   1 }, { "bank",   4 }, { "pohh",   1 },
  { "shred",  2 }, { "store",  1 }, { "sign",   1 }, { "plugin", 1 },
  { "gui",    1 },
  { NULL, 0 }
};

static char const * const FRANK_32X2_MORE_BANK[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "quic",    /*  3 */ "verify",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "resolh",  /*  7 */ "pack",
  /*  8 */ "bank",    /*  9 */ "bank",    /* 10 */ "pohh",    /* 11 */ "shred",
  /* 12 */ "sign",    /* 13 */ "gui",     /* 14 */ _A_,       /* 15 */ _A_,
  /* 16 */ _A_,       /* 17 */ _A_,       /* 18 */ _A_,       /* 19 */ _A_,
  /* 20 */ _A_,       /* 21 */ _A_,       /* 22 */ _A_,       /* 23 */ _A_,
  /* 24 */ _A_,       /* 25 */ _A_,       /* 26 */ _A_,       /* 27 */ _A_,
  /* 28 */ _A_,       /* 29 */ _A_,       /* 30 */ _A_,       /* 31 */ _A_,
  /* --- HT siblings (32-63) --- */
  /* 32 */ __,        /* 33 */ "net",     /* 34 */ "verify",  /* 35 */ "verify",
  /* 36 */ "verify",  /* 37 */ "dedup",   /* 38 */ "bank",    /* 39 */ __,
  /* 40 */ "bank",    /* 41 */ "shred",   /* 42 */ __,        /* 43 */ "store",
  /* 44 */ "plugin",  /* 45 */ __,        /* 46 */ _A_,       /* 47 */ _A_,
  /* 48 */ _A_,       /* 49 */ _A_,       /* 50 */ _A_,       /* 51 */ _A_,
  /* 52 */ _A_,       /* 53 */ _A_,       /* 54 */ _A_,       /* 55 */ _A_,
  /* 56 */ _A_,       /* 57 */ _A_,       /* 58 */ _A_,       /* 59 */ _A_,
  /* 60 */ _A_,       /* 61 */ _A_,       /* 62 */ _A_,       /* 63 */ _A_,
};
#define FRANK_32X2_MORE_BANK_LEN (sizeof(FRANK_32X2_MORE_BANK)/sizeof(FRANK_32X2_MORE_BANK[0]))

/* ---- Variation: Firedancer 32×2, extra blocklist -----------------------
   blocklist = "0h,5h" → {0,32,5,37}. 29 phys avail. 36 tiles > 29.     */

static char const * const FD_32X2_EXTRA_BL[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "quic",    /*  3 */ "verify",
  /*  4 */ "verify",  /*  5 */ __,        /*  6 */ "verify",  /*  7 */ "resolv",
  /*  8 */ "pack",    /*  9 */ "execle",  /* 10 */ "poh",     /* 11 */ "sign",
  /* 12 */ "gui",     /* 13 */ "gossvf",  /* 14 */ "gossip",  /* 15 */ "replay",
  /* 16 */ "execrp",  /* 17 */ "execrp",  /* 18 */ "execrp",  /* 19 */ "execrp",
  /* 20 */ "execrp",  /* 21 */ "tower",   /* 22 */ __,        /* 23 */ __,
  /* 24 */ __,        /* 25 */ __,        /* 26 */ __,        /* 27 */ __,
  /* 28 */ __,        /* 29 */ __,        /* 30 */ __,        /* 31 */ __,
  /* --- HT siblings (32-63) --- */
  /* 32 */ __,        /* 33 */ "net",     /* 34 */ "verify",  /* 35 */ "verify",
  /* 36 */ "verify",  /* 37 */ __,        /* 38 */ "dedup",   /* 39 */ "execle",
  /* 40 */ __,        /* 41 */ "shred",   /* 42 */ __,        /* 43 */ "sign",
  /* 44 */ __,        /* 45 */ "gossvf",  /* 46 */ "repair",  /* 47 */ "execrp",
  /* 48 */ "execrp",  /* 49 */ "execrp",  /* 50 */ "execrp",  /* 51 */ "execrp",
  /* 52 */ "txsend",  /* 53 */ __,        /* 54 */ __,        /* 55 */ __,
  /* 56 */ __,        /* 57 */ __,        /* 58 */ __,        /* 59 */ __,
  /* 60 */ __,        /* 61 */ __,        /* 62 */ __,        /* 63 */ __,
};
#define FD_32X2_EXTRA_BL_LEN (sizeof(FD_32X2_EXTRA_BL)/sizeof(FD_32X2_EXTRA_BL[0]))

#undef __
#undef _A_

/* ======================================================================== */
/*  Test functions                                                          */
/* ======================================================================== */

/* --- Firedancer (no agave) ---------------------------------------------- */

static void test_firedancer_24x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 24 );
  run_test( "firedancer_24x2", 24, FIREDANCER_TILES, bl, 0, FD_24X2_LEN, FD_24X2 );
}

static void test_firedancer_32x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 32 );
  run_test( "firedancer_32x2", 32, FIREDANCER_TILES, bl, 0, FD_32X2_LEN, FD_32X2 );
}

static void test_firedancer_48x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 48 );
  run_test( "firedancer_48x2", 48, FIREDANCER_TILES, bl, 0, FD_SKIP_HT_LEN, FD_SKIP_HT );
}

static void test_firedancer_64x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 64 );
  run_test( "firedancer_64x2", 64, FIREDANCER_TILES, bl, 0, FD_SKIP_HT_LEN, FD_SKIP_HT );
}

static void test_firedancer_128x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 128 );
  run_test( "firedancer_128x2", 128, FIREDANCER_TILES, bl, 0, FD_SKIP_HT_LEN, FD_SKIP_HT );
}

/* --- Frankendancer (with agave visible in expected arrays) -------------- */

static void test_frankendancer_24x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 24 );
  run_test( "frankendancer_24x2", 24, FRANKENDANCER_TILES, bl, 1,
            FRANK_24X2_LEN, FRANK_24X2 );
}

static void test_frankendancer_32x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 32 );
  run_test( "frankendancer_32x2", 32, FRANKENDANCER_TILES, bl, 1,
            FRANK_32X2_LEN, FRANK_32X2 );
}

/* For skip-HT Frankendancer (48/64/128): build the full expected array
   from the shared tile prefix, then mark agave regions with AGAVE.
   Tiles on physical 1-21, agave on physical 22..N-1 and HT N+22..2N-1. */

static void test_frankendancer_48x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 48 );
  char const * expected[96] = {0};
  for( ulong i=0UL; i<FRANK_SKIP_HT_PREFIX_LEN; i++ ) expected[i] = FRANK_SKIP_HT_PREFIX[i];
  for( ulong i=22; i<48;  i++ ) expected[i] = "AGAVE";  /* phys agave  */
  for( ulong i=70; i<96;  i++ ) expected[i] = "AGAVE";  /* HT agave    */
  run_test( "frankendancer_48x2", 48, FRANKENDANCER_TILES, bl, 1, 96, expected );
}

static void test_frankendancer_64x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 64 );
  char const * expected[128] = {0};
  for( ulong i=0UL; i<FRANK_SKIP_HT_PREFIX_LEN; i++ ) expected[i] = FRANK_SKIP_HT_PREFIX[i];
  for( ulong i=22; i<64;   i++ ) expected[i] = "AGAVE";  /* phys agave */
  for( ulong i=86; i<128;  i++ ) expected[i] = "AGAVE";  /* HT agave   */
  run_test( "frankendancer_64x2", 64, FRANKENDANCER_TILES, bl, 1, 128, expected );
}

static void test_frankendancer_128x2( void ) {
  ulong bl[] = BLOCKLIST_0H( 128 );
  char const * expected[256] = {0};
  for( ulong i=0UL; i<FRANK_SKIP_HT_PREFIX_LEN; i++ ) expected[i] = FRANK_SKIP_HT_PREFIX[i];
  for( ulong i=22;  i<128; i++ ) expected[i] = "AGAVE";  /* phys agave */
  for( ulong i=150; i<256; i++ ) expected[i] = "AGAVE";  /* HT agave   */
  run_test( "frankendancer_128x2", 128, FRANKENDANCER_TILES, bl, 1, 256, expected );
}

/* --- Variations on 32×2 ------------------------------------------------ */

static void test_firedancer_32x2_fewer_tiles( void ) {
  ulong bl[] = BLOCKLIST_0H( 32 );
  run_test( "firedancer_32x2_fewer_tiles", 32, FD_FEWER_TILES, bl, 0,
            FD_32X2_FEWER_LEN, FD_32X2_FEWER );
}

static void test_frankendancer_32x2_more_bank( void ) {
  ulong bl[] = BLOCKLIST_0H( 32 );
  run_test( "frankendancer_32x2_more_bank", 32, FRANK_MORE_BANK, bl, 1,
            FRANK_32X2_MORE_BANK_LEN, FRANK_32X2_MORE_BANK );
}

static void test_firedancer_32x2_extra_blocklist( void ) {
  ulong bl[] = { 0, 32, 5, 37, ULONG_MAX };
  run_test( "firedancer_32x2_extra_blocklist", 32, FIREDANCER_TILES, bl, 0,
            FD_32X2_EXTRA_BL_LEN, FD_32X2_EXTRA_BL );
}

/* ======================================================================== */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Firedancer */
  test_firedancer_24x2();
  test_firedancer_32x2();
  test_firedancer_48x2();
  test_firedancer_64x2();
  test_firedancer_128x2();

  /* Frankendancer */
  test_frankendancer_24x2();
  test_frankendancer_32x2();
  test_frankendancer_48x2();
  test_frankendancer_64x2();
  test_frankendancer_128x2();

  /* Variations on 32×2 */
  test_firedancer_32x2_fewer_tiles();
  test_frankendancer_32x2_more_bank();
  test_firedancer_32x2_extra_blocklist();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
