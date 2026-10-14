#define _GNU_SOURCE

/* test_topob.c – unit tests for CPU topology and fd_topob_auto_layout_cpus.

   Tests verify the auto-layout algorithm on synthetic CPU topologies
   for various core counts, tile sets, and blocklists.

   Each test supplies:
     - a synthetic CPU topology  (physical cores × 2 with HT siblings)
     - a tile set                (tile names and counts)
     - a blocklist               (core indices to exclude)
     - an expected per-CPU array:
         expected[cpu] = tile name   →  tile assigned to that cpu
         expected[cpu] = NULL (__)   →  cpu unassigned                 */

#include "fd_topob.h"
#include "fd_cpu_topo.c"
#include "../../util/tile/fd_tile_private.h"
#include "../../util/tmpl/fd_unit_test.c"

#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- CPU topology ------------------------------------------------------ */

FD_UNIT_TEST( test_cpu_topo_parse ) {
  struct {
    char const * text;
    int          expected;
  } const cases[] = {
    { "0",                    0       },
    { "0\n",                  0       },
    { "42\n",                 42      },
    { "2147483647\n",         INT_MAX },
    { "2147483648\n",         -1      },
    { "18446744073709551616", -1      },
    { "-1\n",                 -1      },
    { "-2\n",                 -1      },
    { "",                     -1      },
    { "\n",                   -1      },
    { "abc\n",                -1      },
    { "12x\n",                -1      },
    { "0\n1\n",               -1      },
    { "0\n\n",                -1      }
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    FD_TEST( parse_topology_id( cases[ i ].text, strlen( cases[ i ].text ) )==cases[ i ].expected );
  }
  FD_TEST( parse_topology_id( "1\0junk", 6UL )==-1 );
}

FD_UNIT_TEST( test_cpu_topo_cpulist ) {
  FD_CPUSET_DECL( set );
  FD_TEST( parse_cpulist( "", set ) && !fd_cpuset_cnt( set ) );
  FD_TEST( parse_cpulist( "\n", set ) && !fd_cpuset_cnt( set ) );
  FD_TEST( parse_cpulist( "(null)\n", set ) && !fd_cpuset_cnt( set ) );
  FD_TEST( parse_cpulist( "      (null)\n", set ) && !fd_cpuset_cnt( set ) );
  FD_TEST( parse_cpulist( "2,34\n", set ) && fd_cpuset_cnt( set )==2UL && fd_cpuset_test( set, 2UL ) && fd_cpuset_test( set, 34UL ) );
  FD_TEST( parse_cpulist( "1-3,7", set ) && fd_cpuset_cnt( set )==4UL && fd_cpuset_test( set, 7UL ) );
  FD_TEST( !parse_cpulist( "3-1\n", set ) );
  FD_TEST( !parse_cpulist( "1;2\n", set ) );
  FD_TEST( !parse_cpulist( "x\n", set ) );
}

FD_UNIT_TEST( test_cpu_topo_read ) {
  int fd = memfd_create( "test_topob", 0U );
  FD_TEST( fd>=0 );
  char path[ 64 ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/self/fd/%i", fd ) );
  FD_TEST( read_topology_id( path )==-1 );

  char const * cases[] = { "7\n", "-1\n", "2147483648\n", "not a die\n" };
  int expected[] = { 7, -1, -1, -1 };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    FD_TEST( !ftruncate( fd, 0 ) );
    FD_TEST( lseek( fd, 0, SEEK_SET )==0 );
    ulong sz;
    FD_TEST( !fd_io_write( fd, cases[ i ], strlen( cases[ i ] ), strlen( cases[ i ] ), &sz ) );
    FD_TEST( read_topology_id( path )==expected[ i ] );
  }
  char oversized[ 128 ];
  memset( oversized, '0', sizeof(oversized) );
  FD_TEST( !ftruncate( fd, 0 ) );
  FD_TEST( lseek( fd, 0, SEEK_SET )==0 );
  ulong sz;
  FD_TEST( !fd_io_write( fd, oversized, sizeof(oversized), sizeof(oversized), &sz ) );
  FD_TEST( read_topology_id( path )==-1 );
  FD_TEST( !close( fd ) );
  FD_TEST( read_topology_id( path )==-1 );
}

FD_UNIT_TEST( test_cpu_topo_assign ) {
  fd_topo_cpus_t cpus[ 1 ];
  memset( cpus, 0, sizeof(cpus) );
  int package_ids[ FD_TILE_MAX ];
  int die_ids    [ FD_TILE_MAX ];
  cpus->cpu_cnt = FD_TILE_MAX;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    cpus->cpu[ i ].idx = i;
    cpus->cpu[ i ].online = (int)(i%2UL);
    cpus->cpu[ i ].die_idx = 42UL;
    package_ids[ i ] = -1;
    die_ids[ i ] = -1;
  }
  assign_die_indices( cpus, package_ids, die_ids );
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) FD_TEST( cpus->cpu[ i ].die_idx==ULONG_MAX );

  int const packages[] = { -1, 2, 2, 2, 8, 2, 8, -1, 2, INT_MAX };
  int const dies[]     = {  0, 4, 9, 4, 4, -1, 4, 7, 9, INT_MAX };
  ulong const expected[] = { ULONG_MAX, 0UL, 1UL, 0UL, 2UL, ULONG_MAX, 2UL, ULONG_MAX, 1UL, 3UL };
  cpus->cpu_cnt = sizeof(packages)/sizeof(packages[0]);
  for( ulong run=0UL; run<2UL; run++ ) {
    assign_die_indices( cpus, packages, dies );
    for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
      FD_TEST( cpus->cpu[ i ].die_idx==expected[ i ] );
      FD_TEST( cpus->cpu[ i ].idx==i );
      FD_TEST( cpus->cpu[ i ].online==(int)(i%2UL) );
    }
  }

  cpus->cpu_cnt = FD_TILE_MAX;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    package_ids[ i ] = (int)(i/2UL);
    die_ids[ i ] = (int)(i%2UL);
  }
  assign_die_indices( cpus, package_ids, die_ids );
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) FD_TEST( cpus->cpu[ i ].die_idx==i );

  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    package_ids[ i ] = 0;
    die_ids[ i ] = 0;
  }
  assign_die_indices( cpus, package_ids, die_ids );
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) FD_TEST( cpus->cpu[ i ].die_idx==0UL );

  /* L3 ids are qualified by package: the same cache id on two packages
     is two domains, an unknown package or id is no domain, and the
     dense indices are assigned in CPU order. */
  int const l3_packages[] = {  0,  0,  1,  1,  0, -1,  1,  0 };
  int const l3_ids[]      = {  5,  5,  5,  9,  9,  5, -1,  5 };
  ulong const l3_expected[] = { 0UL, 0UL, 1UL, 2UL, 3UL, ULONG_MAX, ULONG_MAX, 0UL };
  cpus->cpu_cnt = sizeof(l3_packages)/sizeof(l3_packages[0]);
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) cpus->cpu[ i ].online = 1;
  assign_l3_indices( cpus, l3_packages, l3_ids );
  FD_TEST( cpus->l3_cnt==4UL );
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) FD_TEST( cpus->cpu[ i ].l3_idx==l3_expected[ i ] );
  FD_TEST( !fd_topo_cpus_l3_complete( cpus ) ); /* two CPUs without a domain */
  cpus->cpu[ 5 ].online = 0; cpus->cpu[ 6 ].online = 0;
  FD_TEST( fd_topo_cpus_l3_complete( cpus ) );  /* offline CPUs do not count */

  cpus->cpu_cnt = FD_TILE_MAX;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) { package_ids[ i ] = 0; die_ids[ i ] = 3; cpus->cpu[ i ].online = 1; }
  assign_l3_indices( cpus, package_ids, die_ids );
  FD_TEST( cpus->l3_cnt==1UL );
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) FD_TEST( cpus->cpu[ i ].l3_idx==0UL );
  FD_TEST( !fd_topo_cpus_l3_complete( cpus ) ); /* one domain: nothing to pack */
}

/* ---- Tile specification ------------------------------------------------ */

typedef struct { char const * name; ulong cnt; } tile_spec_t;

/* ---- Helpers ----------------------------------------------------------- */

/* Create a synthetic HT CPU topology.
   physical_cores physical cores on a single NUMA node.
   Core i has HT sibling at physical_cores+i.
   Total logical CPUs = 2 * physical_cores.
   l3_cores physical cores share an L3 (0: no cache topology). */
static void
make_cpus( fd_topo_cpus_t * cpus,
           ulong            physical_cores,
           ulong            l3_cores ) {
  fd_memset( cpus, 0, sizeof(*cpus) );
  cpus->numa_node_cnt = 1UL;
  cpus->l3_cnt        = l3_cores ? (physical_cores+l3_cores-1UL)/l3_cores : 0UL;
  cpus->cpu_cnt       = 2UL * physical_cores;
  for( ulong i=0UL; i<physical_cores; i++ ) {
    cpus->cpu[ i ].idx       = i;
    cpus->cpu[ i ].online    = 1;
    cpus->cpu[ i ].numa_node = 0UL;
    cpus->cpu[ i ].sibling   = physical_cores + i;
    cpus->cpu[ i ].die_idx   = 0UL;
    cpus->cpu[ i ].l3_idx    = l3_cores ? i/l3_cores : ULONG_MAX;
  }
  for( ulong i=0UL; i<physical_cores; i++ ) {
    ulong s = physical_cores + i;
    cpus->cpu[ s ].idx       = s;
    cpus->cpu[ s ].online    = 1;
    cpus->cpu[ s ].numa_node = 0UL;
    cpus->cpu[ s ].sibling   = i;
    cpus->cpu[ s ].die_idx   = 0UL;
    cpus->cpu[ s ].l3_idx    = cpus->cpu[ i ].l3_idx;
  }
}

/* Take the listed CPUs offline as the kernel reports them: no sibling
   or cache, and the online partner loses its sibling.  offline[] is
   terminated by ULONG_MAX, NULL for none. */
static void
make_cpus_offline( fd_topo_cpus_t * cpus,
                   ulong const *    offline ) {
  for( ulong const * p = offline; p && *p!=ULONG_MAX; p++ ) {
    fd_topo_cpu_t * cpu = &cpus->cpu[ *p ];
    if( cpu->sibling!=ULONG_MAX ) cpus->cpu[ cpu->sibling ].sibling = ULONG_MAX;
    cpu->online  = 0;
    cpu->sibling = ULONG_MAX;
    cpu->l3_idx  = ULONG_MAX;
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
   Tiles get their tile name, rest NULL. */
static void
build_cpu_map( fd_topo_t const * topo,
               ulong             cpu_cnt,
               char const **     out ) {
  for( ulong i=0UL; i<cpu_cnt; i++ ) out[ i ] = NULL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ulong c = topo->tiles[ i ].cpu_idx;
    if( c != ULONG_MAX && c < cpu_cnt ) out[ c ] = topo->tiles[ i ].name;
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

/* Verify the layout of tiles matches expected[].
   expected[i] = tile name  →  tile should be assigned to cpu i
   expected[i] = NULL       →  cpu unassigned (blocked / unused)
   Entries beyond expected_len must also be unassigned. */
static void
run_layout( ulong                 physical_cores,
            ulong                 l3_cores,
            ulong const *         offline,        /* ULONG_MAX terminated, NULL for none */
            int                   efficient,
            tile_spec_t const *   tiles,
            ulong const *         blocklist,      /* ULONG_MAX terminated */
            ulong                 expected_len,
            char const * const *  expected ) {
  /* Build CPU topology */
  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, physical_cores, l3_cores );
  make_cpus_offline( cpus, offline );
  ulong cpu_cnt = cpus->cpu_cnt;

  /* Build tile topology */
  static fd_topo_t _topo[1];   /* static – too large for stack */
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, tiles );
  set_blocklist( topo, blocklist );
  topo->sleep_obj_id = efficient ? 0UL : ULONG_MAX; /* fd_topob_sleep sets it in efficient mode */

  /* Run the layout algorithm */
  fd_topob_auto_layout_cpus( topo, cpus );

  /* Build actual per-CPU map */
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
}

static void
run_test( ulong                 physical_cores,
          tile_spec_t const *   tiles,
          ulong const *         blocklist,      /* ULONG_MAX terminated */
          ulong                 expected_len,
          char const * const *  expected ) {
  run_layout( physical_cores, 0UL, NULL, 0, tiles, blocklist, expected_len, expected );
}

/* ======================================================================== */
/*  Tile definitions                                                        */
/* ======================================================================== */

/* --- Firedancer default (no snapshots, no rpc, no telemetry) -- */

static tile_spec_t const FIREDANCER_TILES[] = {
  /* floating tiles */
  { "netlnk", 1 },
  { "metric", 1 }, { "diag",   1 }, { "genesi", 1 }, { "ipecho", 1 },
  { "admin",  1 },
  /* ordered tiles (36) */
  { "net",    2 }, { "quic",   1 }, { "verify", 6 }, { "dedup",  1 },
  { "resolv", 1 }, { "pack",   1 }, { "execle", 2 }, { "poh",    1 },
  { "shred",  1 }, { "sign",   2 }, { "gui",    1 }, { "gossvf", 2 },
  { "gossip", 1 }, { "repair", 1 }, { "replay", 1 }, { "execrp",10 },
  { "txsend", 1 }, { "tower",  1 },
  { NULL, 0 }
};

/* --- Firedancer default in efficient mode (adds the mwaitx tile) -------- */

static tile_spec_t const FIREDANCER_EFF_TILES[] = {
  { "netlnk", 1 },
  { "metric", 1 }, { "diag",   1 }, { "genesi", 1 }, { "ipecho", 1 },
  { "admin",  1 }, { "waker",  1 },
  { "mwaitx", 1 },
  { "net",    2 }, { "quic",   1 }, { "verify", 6 }, { "dedup",  1 },
  { "resolv", 1 }, { "pack",   1 }, { "execle", 2 }, { "poh",    1 },
  { "shred",  1 }, { "sign",   2 }, { "gui",    1 }, { "gossvf", 2 },
  { "gossip", 1 }, { "repair", 1 }, { "replay", 1 }, { "execrp",10 },
  { "txsend", 1 }, { "tower",  1 },
  { NULL, 0 }
};

/* ======================================================================== */
/*  Blocklists                                                              */
/* ======================================================================== */

/* Default "0h" blocklist for N physical cores:
   cores 0 and N are blocked.  Built per-test as a local array. */

#define BLOCKLIST_0H( N ) (ulong const[]){ 0, (N), ULONG_MAX }

/* ======================================================================== */
/*  Expected results                                                        */
/*                                                                          */
/*  For each test, expected[cpu] = tile name or __ (unused).                */
/* ======================================================================== */

#define __ NULL

/* ---- Firedancer, skip-HT expected prefix (48/64/128 physical) ----------
   When enough physical cores, ALWAYS tiles on cores 1..21, then
   POST_START tiles on cores 22..36.  HT siblings all unassigned.          */

static char const * const FD_SKIP_HT[] = {
  /* phys cores 0-36 (ALWAYS 1-22, POST_START 23-36) */
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "net",     /*  3 */ "quic",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "verify",  /*  7 */ "verify",
  /*  8 */ "verify",  /*  9 */ "verify",  /* 10 */ "dedup",   /* 11 */ "resolv",
  /* 12 */ "pack",    /* 13 */ "sign",    /* 14 */ "sign",    /* 15 */ "shred",
  /* 16 */ "gui",     /* 17 */ "gossvf",  /* 18 */ "gossvf",  /* 19 */ "gossip",
  /* 20 */ "repair",  /* 21 */ "replay",  /* 22 */ "tower",   /* 23 */ "execle",
  /* 24 */ "execle",  /* 25 */ "poh",     /* 26 */ "execrp",  /* 27 */ "execrp",
  /* 28 */ "execrp",  /* 29 */ "execrp",  /* 30 */ "execrp",  /* 31 */ "execrp",
  /* 32 */ "execrp",  /* 33 */ "execrp",  /* 34 */ "execrp",  /* 35 */ "execrp",
  /* 36 */ "txsend",
};
#define FD_SKIP_HT_LEN (sizeof(FD_SKIP_HT)/sizeof(FD_SKIP_HT[0]))

/* ---- Firedancer efficient mode, skip-HT, no L3 packing -----------------
   FD_SKIP_HT with the mwaitx tile last in ALWAYS: one L3 domain (or no
   cache topology) keeps the sequential layout.                           */

static char const * const FD_EFF_SKIP_HT[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "net",     /*  3 */ "quic",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "verify",  /*  7 */ "verify",
  /*  8 */ "verify",  /*  9 */ "verify",  /* 10 */ "dedup",   /* 11 */ "resolv",
  /* 12 */ "pack",    /* 13 */ "sign",    /* 14 */ "sign",    /* 15 */ "shred",
  /* 16 */ "gui",     /* 17 */ "gossvf",  /* 18 */ "gossvf",  /* 19 */ "gossip",
  /* 20 */ "repair",  /* 21 */ "replay",  /* 22 */ "tower",   /* 23 */ "mwaitx",
  /* 24 */ "execle",  /* 25 */ "execle",  /* 26 */ "poh",     /* 27 */ "execrp",
  /* 28 */ "execrp",  /* 29 */ "execrp",  /* 30 */ "execrp",  /* 31 */ "execrp",
  /* 32 */ "execrp",  /* 33 */ "execrp",  /* 34 */ "execrp",  /* 35 */ "execrp",
  /* 36 */ "execrp",  /* 37 */ "txsend",
};
#define FD_EFF_SKIP_HT_LEN (sizeof(FD_EFF_SKIP_HT)/sizeof(FD_EFF_SKIP_HT[0]))

/* ---- Firedancer efficient mode, 48x2 in 8 L3 domains of 6 cores --------
   Core 0 is blocked so L3 0 has 5 free cores and the hot pinned tiles
   start in L3 1: mwaitx, replay and execrp fill L3 1-2.  The other
   ALWAYS tiles then take the free cores in sequence (net, quic and
   verify fill L3 0 first), the POST_START tiles last.  Floating tiles
   are not packed: their cpu_idx only picks a NUMA node.               */

static char const * const FD_EFF_48X2_L3[] = {
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "net",     /*  3 */ "quic",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "mwaitx",  /*  7 */ "replay",
  /*  8 */ "execrp",  /*  9 */ "execrp",  /* 10 */ "execrp",  /* 11 */ "execrp",
  /* 12 */ "execrp",  /* 13 */ "execrp",  /* 14 */ "execrp",  /* 15 */ "execrp",
  /* 16 */ "execrp",  /* 17 */ "execrp",  /* 18 */ "verify",  /* 19 */ "verify",
  /* 20 */ "verify",  /* 21 */ "verify",  /* 22 */ "dedup",   /* 23 */ "resolv",
  /* 24 */ "pack",    /* 25 */ "sign",    /* 26 */ "sign",    /* 27 */ "shred",
  /* 28 */ "gui",     /* 29 */ "gossvf",  /* 30 */ "gossvf",  /* 31 */ "gossip",
  /* 32 */ "repair",  /* 33 */ "tower",   /* 34 */ "execle",  /* 35 */ "execle",
  /* 36 */ "poh",     /* 37 */ "txsend",
};
#define FD_EFF_48X2_L3_LEN (sizeof(FD_EFF_48X2_L3)/sizeof(FD_EFF_48X2_L3[0]))

/* ---- Firedancer performance mode, 48x2 in 8 L3 domains of 6 cores -----
   FD_SKIP_HT with pack, poh and execle first in the 5 free cores of L3
   0 (no accdb in this tile set), the rest in sequence after them.      */

static char const * const FD_48X2_L3_PERF[] = {
  /*  0 */ __,        /*  1 */ "pack",    /*  2 */ "poh",     /*  3 */ "execle",
  /*  4 */ "execle",  /*  5 */ "net",     /*  6 */ "net",     /*  7 */ "quic",
  /*  8 */ "verify",  /*  9 */ "verify",  /* 10 */ "verify",  /* 11 */ "verify",
  /* 12 */ "verify",  /* 13 */ "verify",  /* 14 */ "dedup",   /* 15 */ "resolv",
  /* 16 */ "sign",    /* 17 */ "sign",    /* 18 */ "shred",   /* 19 */ "gui",
  /* 20 */ "gossvf",  /* 21 */ "gossvf",  /* 22 */ "gossip",  /* 23 */ "repair",
  /* 24 */ "replay",  /* 25 */ "tower",   /* 26 */ "execrp",  /* 27 */ "execrp",
  /* 28 */ "execrp",  /* 29 */ "execrp",  /* 30 */ "execrp",  /* 31 */ "execrp",
  /* 32 */ "execrp",  /* 33 */ "execrp",  /* 34 */ "execrp",  /* 35 */ "execrp",
  /* 36 */ "txsend",
};
#define FD_48X2_L3_PERF_LEN (sizeof(FD_48X2_L3_PERF)/sizeof(FD_48X2_L3_PERF[0]))

/* ---- Firedancer 24×2  (no skip HT, 36 tiles > 23 physical cores) ------
   13 cores shared: pack and poh alone, execrp:0..7 whole, replay, tower,
   shred and net:0 next to cold tiles.                                    */

static char const * const FD_24X2[] = {
  /*  0 */ __,       /*  1 */ "net",    /*  2 */ "net",    /*  3 */ "quic",
  /*  4 */ "verify", /*  5 */ "verify", /*  6 */ "verify", /*  7 */ "pack",
  /*  8 */ "sign",   /*  9 */ "sign",   /* 10 */ "shred",  /* 11 */ "gui",
  /* 12 */ "gossvf", /* 13 */ "execle", /* 14 */ "poh",    /* 15 */ "execrp",
  /* 16 */ "execrp", /* 17 */ "execrp", /* 18 */ "execrp", /* 19 */ "execrp",
  /* 20 */ "execrp", /* 21 */ "execrp", /* 22 */ "execrp", /* 23 */ "execrp",
  /* --- HT siblings (24-47) --- */
  /* 24 */ __,       /* 25 */ "gossip", /* 26 */ "dedup",  /* 27 */ "resolv",
  /* 28 */ "verify", /* 29 */ "verify", /* 30 */ "verify", /* 31 */ __,
  /* 32 */ "txsend", /* 33 */ "replay", /* 34 */ "gossvf", /* 35 */ "repair",
  /* 36 */ "tower",  /* 37 */ "execle", /* 38 */ __,       /* 39 */ __,
  /* 40 */ __,       /* 41 */ __,       /* 42 */ __,       /* 43 */ __,
  /* 44 */ __,       /* 45 */ __,       /* 46 */ __,       /* 47 */ "execrp",
};
#define FD_24X2_LEN (sizeof(FD_24X2)/sizeof(FD_24X2[0]))

/* ---- Firedancer 32×2  (no skip HT, 36 tiles > 31 physical cores) ------
   5 cores shared, no core left idle.                                     */

static char const * const FD_32X2[] = {
  /*  0 */ __,       /*  1 */ "net",    /*  2 */ "net",    /*  3 */ "quic",
  /*  4 */ "verify", /*  5 */ "verify", /*  6 */ "verify", /*  7 */ "verify",
  /*  8 */ "verify", /*  9 */ "dedup",  /* 10 */ "resolv", /* 11 */ "pack",
  /* 12 */ "sign",   /* 13 */ "sign",   /* 14 */ "shred",  /* 15 */ "gossvf",
  /* 16 */ "repair", /* 17 */ "replay", /* 18 */ "tower",  /* 19 */ "execle",
  /* 20 */ "execle", /* 21 */ "poh",    /* 22 */ "execrp", /* 23 */ "execrp",
  /* 24 */ "execrp", /* 25 */ "execrp", /* 26 */ "execrp", /* 27 */ "execrp",
  /* 28 */ "execrp", /* 29 */ "execrp", /* 30 */ "execrp", /* 31 */ "execrp",
  /* --- HT siblings (32-63) --- */
  /* 32 */ __,       /* 33 */ __,       /* 34 */ "txsend", /* 35 */ __,
  /* 36 */ __,       /* 37 */ __,       /* 38 */ __,       /* 39 */ "verify",
  /* 40 */ "gossvf", /* 41 */ __,       /* 42 */ __,       /* 43 */ __,
  /* 44 */ __,       /* 45 */ "gui",    /* 46 */ __,       /* 47 */ "gossip",
};
#define FD_32X2_LEN (sizeof(FD_32X2)/sizeof(FD_32X2[0]))

/* ---- Variation: Firedancer 32×2, fewer tiles → skip HT -----------------
   verify=2, execrp=4  →  26 tiles total, 31 available ≥ 26              */

static tile_spec_t const FD_FEWER_TILES[] = {
  { "netlnk", 1 },
  { "metric", 1 }, { "diag",   1 }, { "genesi", 1 }, { "ipecho", 1 },
  { "admin",  1 },
  { "net",    2 }, { "quic",   1 }, { "verify", 2 }, { "dedup",  1 },
  { "resolv", 1 }, { "pack",   1 }, { "execle", 2 }, { "poh",    1 },
  { "shred",  1 }, { "sign",   2 }, { "gui",    1 }, { "gossvf", 2 },
  { "gossip", 1 }, { "repair", 1 }, { "replay", 1 }, { "execrp", 4 },
  { "txsend", 1 }, { "tower",  1 },
  { NULL, 0 }
};

static char const * const FD_32X2_FEWER[] = {
  /* skip_ht: ALWAYS on cores 1..18, POST_START on cores 19..26 */
  /*  0 */ __,        /*  1 */ "net",     /*  2 */ "net",     /*  3 */ "quic",
  /*  4 */ "verify",  /*  5 */ "verify",  /*  6 */ "dedup",   /*  7 */ "resolv",
  /*  8 */ "pack",    /*  9 */ "sign",    /* 10 */ "sign",    /* 11 */ "shred",
  /* 12 */ "gui",     /* 13 */ "gossvf",  /* 14 */ "gossvf",  /* 15 */ "gossip",
  /* 16 */ "repair",  /* 17 */ "replay",  /* 18 */ "tower",   /* 19 */ "execle",
  /* 20 */ "execle",  /* 21 */ "poh",     /* 22 */ "execrp",  /* 23 */ "execrp",
  /* 24 */ "execrp",  /* 25 */ "execrp",  /* 26 */ "txsend",
};
#define FD_32X2_FEWER_LEN (sizeof(FD_32X2_FEWER)/sizeof(FD_32X2_FEWER[0]))

/* ---- Variation: Firedancer 32×2, extra blocklist -----------------------
   blocklist = "0h,5h" → {0,32,5,37}. 30 phys avail. 36 tiles > 30.     */

static char const * const FD_32X2_EXTRA_BL[] = {
  /*  0 */ __,       /*  1 */ "net",    /*  2 */ "net",    /*  3 */ "quic",
  /*  4 */ "verify", /*  5 */ __,       /*  6 */ "verify", /*  7 */ "verify",
  /*  8 */ "verify", /*  9 */ "dedup",  /* 10 */ "resolv", /* 11 */ "pack",
  /* 12 */ "sign",   /* 13 */ "sign",   /* 14 */ "shred",  /* 15 */ "gossvf",
  /* 16 */ "repair", /* 17 */ "replay", /* 18 */ "tower",  /* 19 */ "execle",
  /* 20 */ "execle", /* 21 */ "poh",    /* 22 */ "execrp", /* 23 */ "execrp",
  /* 24 */ "execrp", /* 25 */ "execrp", /* 26 */ "execrp", /* 27 */ "execrp",
  /* 28 */ "execrp", /* 29 */ "execrp", /* 30 */ "execrp", /* 31 */ "execrp",
  /* --- HT siblings (32-63) --- */
  /* 32 */ __,       /* 33 */ __,       /* 34 */ "txsend", /* 35 */ __,
  /* 36 */ __,       /* 37 */ __,       /* 38 */ "verify", /* 39 */ "verify",
  /* 40 */ "gossvf", /* 41 */ __,       /* 42 */ __,       /* 43 */ __,
  /* 44 */ __,       /* 45 */ "gui",    /* 46 */ __,       /* 47 */ "gossip",
};
#define FD_32X2_EXTRA_BL_LEN (sizeof(FD_32X2_EXTRA_BL)/sizeof(FD_32X2_EXTRA_BL[0]))

#undef __

/* ======================================================================== */
/*  Test functions                                                          */
/* ======================================================================== */

/* --- Firedancer --------------------------------------------------------- */

FD_UNIT_TEST( test_firedancer_24x2 ) {
  run_test( 24, FIREDANCER_TILES, BLOCKLIST_0H( 24 ), FD_24X2_LEN, FD_24X2 );
}

/* Spare cores go to execrp in kind_id order: on 24x2 execrp:0..7 get a
   physical core to themselves and only the last two share. */

FD_UNIT_TEST( test_execrp_dedicated_order ) {
  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 24, 0 );
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, FIREDANCER_TILES );
  set_blocklist( topo, BLOCKLIST_0H( 24 ) );
  topo->sleep_obj_id = ULONG_MAX;
  fd_topob_auto_layout_cpus( topo, cpus );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( strcmp( tile->name, "execrp" ) ) continue;
    ulong sibling = cpus->cpu[ tile->cpu_idx ].sibling;
    FD_TEST( sibling!=ULONG_MAX );
    int   shared  = 0;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) shared |= topo->tiles[ j ].cpu_idx==sibling;
    FD_TEST( shared==(tile->kind_id>=8UL) );
  }
}

/* Blocklisting one side of some HT pairs leaves spare logical CPUs
   that are half cores */
FD_UNIT_TEST( test_execrp_dedicated_half_cores ) {
  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 32, 0 );
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, FIREDANCER_TILES );
  set_blocklist( topo, (ulong const[]){ 0, 32, 24, 25, 26, 27, 28, 29, 30, 31, ULONG_MAX } );
  topo->sleep_obj_id = ULONG_MAX;
  fd_topob_auto_layout_cpus( topo, cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( !strcmp( topo->tiles[ i ].name, "execrp" ) ) FD_TEST( topo->tiles[ i ].cpu_idx!=ULONG_MAX );
  }
}

FD_UNIT_TEST( test_firedancer_32x2 ) {
  run_test( 32, FIREDANCER_TILES, BLOCKLIST_0H( 32 ), FD_32X2_LEN, FD_32X2 );
}

FD_UNIT_TEST( test_firedancer_48x2 ) {
  run_test( 48, FIREDANCER_TILES, BLOCKLIST_0H( 48 ), FD_SKIP_HT_LEN, FD_SKIP_HT );
}

FD_UNIT_TEST( test_firedancer_64x2 ) {
  run_test( 64, FIREDANCER_TILES, BLOCKLIST_0H( 64 ), FD_SKIP_HT_LEN, FD_SKIP_HT );
}

FD_UNIT_TEST( test_firedancer_128x2 ) {
  run_test( 128, FIREDANCER_TILES, BLOCKLIST_0H( 128 ), FD_SKIP_HT_LEN, FD_SKIP_HT );
}

/* --- Firedancer efficient mode ------------------------------------------ */

/* Performance mode only places pack, poh and execle by L3 */
FD_UNIT_TEST( test_firedancer_48x2_l3_performance ) {
  run_layout( 48, 6, NULL, 0, FIREDANCER_TILES, BLOCKLIST_0H( 48 ), FD_48X2_L3_PERF_LEN, FD_48X2_L3_PERF );
}

/* One L3 domain, or none known, keeps the sequential layout */
FD_UNIT_TEST( test_firedancer_48x2_efficient_one_l3 ) {
  run_layout( 48, 48, NULL, 1, FIREDANCER_EFF_TILES, BLOCKLIST_0H( 48 ), FD_EFF_SKIP_HT_LEN, FD_EFF_SKIP_HT );
  run_layout( 48,  0, NULL, 1, FIREDANCER_EFF_TILES, BLOCKLIST_0H( 48 ), FD_EFF_SKIP_HT_LEN, FD_EFF_SKIP_HT );
}

FD_UNIT_TEST( test_firedancer_48x2_efficient_l3 ) {
  run_layout( 48, 6, NULL, 1, FIREDANCER_EFF_TILES, BLOCKLIST_0H( 48 ), FD_EFF_48X2_L3_LEN, FD_EFF_48X2_L3 );
}

/* Too few cores to give every hot tile its own: sequential layout */
FD_UNIT_TEST( test_firedancer_32x2_efficient_l3 ) {
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, FIREDANCER_EFF_TILES );
  set_blocklist( topo, BLOCKLIST_0H( 32 ) );

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 32, 0 );
  fd_topob_auto_layout_cpus( topo, cpus );
  ulong expected[ FD_TOPO_MAX_TILES ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) expected[ i ] = topo->tiles[ i ].cpu_idx;

  make_cpus( cpus, 32, 6 );
  topo->sleep_obj_id = 0UL;
  fd_topob_auto_layout_cpus( topo, cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) FD_TEST( topo->tiles[ i ].cpu_idx==expected[ i ] );
}

/* --- Variations on 32×2 ------------------------------------------------ */

FD_UNIT_TEST( test_firedancer_32x2_fewer_tiles ) {
  run_test( 32, FD_FEWER_TILES, BLOCKLIST_0H( 32 ),
            FD_32X2_FEWER_LEN, FD_32X2_FEWER );
}

FD_UNIT_TEST( test_firedancer_32x2_extra_blocklist ) {
  run_test( 32, FIREDANCER_TILES, (ulong[]){ 0, 32, 5, 37, ULONG_MAX },
            FD_32X2_EXTRA_BL_LEN, FD_32X2_EXTRA_BL );
}

/* --- Offline CPUs ------------------------------------------------------- */

/* Lay out tiles on physical_cores x 2 with the offline CPUs removed and
   check no tile lands on one.  Returns the topology. */
static fd_topo_t *
layout_offline( ulong               physical_cores,
                ulong const *       offline,
                tile_spec_t const * tiles ) {
  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, physical_cores, 0UL );
  make_cpus_offline( cpus, offline );
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, tiles );
  set_blocklist( topo, BLOCKLIST_0H( physical_cores ) );
  topo->sleep_obj_id = ULONG_MAX;
  fd_topob_auto_layout_cpus( topo, cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ulong cpu = topo->tiles[ i ].cpu_idx;
    if( cpu!=ULONG_MAX ) FD_TEST( cpus->cpu[ cpu ].online );
  }
  return topo;
}

/* An auto layout that runs out of CPUs is a FD_LOG_ERR */
static void
layout_offline_fails( ulong               physical_cores,
                      ulong const *       offline,
                      tile_spec_t const * tiles ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( pid==0 ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_core_set( 5 );
    layout_offline( physical_cores, offline, tiles );
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
}

/* Runtime SMT off: the siblings are present but offline, so a host has
   only its physical cores */
FD_UNIT_TEST( test_offline_smt_off ) {
  ulong offline[ 49 ];
  for( ulong i=0UL; i<48UL; i++ ) offline[ i ] = 48UL+i;
  offline[ 48 ] = ULONG_MAX;
  run_layout( 48, 0, offline, 0, FIREDANCER_TILES, (ulong const[]){ 0, ULONG_MAX }, FD_SKIP_HT_LEN, FD_SKIP_HT );

  for( ulong i=0UL; i<32UL; i++ ) offline[ i ] = 32UL+i;
  offline[ 32 ] = ULONG_MAX;
  run_layout( 32, 0, offline, 0, FD_FEWER_TILES, (ulong const[]){ 0, ULONG_MAX }, FD_32X2_FEWER_LEN, FD_32X2_FEWER );
  layout_offline_fails( 32, offline, FIREDANCER_TILES );
}

/* A low index offline CPU (#4428) is skipped and its sibling becomes a
   whole core */
FD_UNIT_TEST( test_offline_low_index ) {
  for( ulong off=5UL; off<=13UL; off+=8UL ) {
    fd_topo_t * topo = layout_offline( 24, (ulong const[]){ off, ULONG_MAX }, FIREDANCER_TILES );
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) FD_TEST( topo->tiles[ i ].cpu_idx!=ULONG_MAX || fd_topob_tile_priority_type( &topo->tiles[ i ] )==FD_TOPOB_PRIORITY_FLOATING );
  }
}

/* 36x2 is one physical core short of skipping HT pairs.  Offline
   siblings must not count as free cores: with them the layout would
   skip pairs and place tiles on the offline CPUs. */
FD_UNIT_TEST( test_offline_skip_ht_threshold ) {
  fd_topo_t * topo = layout_offline( 36, (ulong const[]){ 48, 61, ULONG_MAX }, FIREDANCER_TILES );
  int on_sibling = 0;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) on_sibling |= topo->tiles[ i ].cpu_idx!=ULONG_MAX && topo->tiles[ i ].cpu_idx>=36UL;
  FD_TEST( on_sibling );
}

/* Unused siblings of critical tiles taken offline change nothing */
FD_UNIT_TEST( test_offline_critical_siblings ) {
  run_layout( 48, 6, (ulong const[]){ 72, 84, ULONG_MAX }, 1, FIREDANCER_EFF_TILES, BLOCKLIST_0H( 48 ), FD_EFF_48X2_L3_LEN, FD_EFF_48X2_L3 );
}

/* --- Adjacent sibling enumeration (cpu i pairs with i^1) ---------------- */

FD_UNIT_TEST( test_adjacent_siblings ) {
  for( int efficient=0; efficient<2; efficient++ ) {
    fd_topo_cpus_t cpus[1];
    make_cpus( cpus, 48, efficient ? 6UL : 0UL );
    for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
      cpus->cpu[ i ].sibling = i^1UL;
      cpus->cpu[ i ].l3_idx  = efficient ? (i/2UL)/6UL : ULONG_MAX;
    }
    static fd_topo_t _topo[1];
    fd_topo_t * topo = _topo;
    fd_memset( topo, 0, sizeof(*topo) );
    make_tiles( topo, efficient ? FIREDANCER_EFF_TILES : FIREDANCER_TILES );
    set_blocklist( topo, (ulong const[]){ 0, 1, ULONG_MAX } );
    topo->sleep_obj_id = efficient ? 0UL : ULONG_MAX;
    fd_topob_auto_layout_cpus( topo, cpus );

    /* 47 free cores fit every pinned tile on a whole core */
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      ulong cpu = topo->tiles[ i ].cpu_idx;
      if( cpu==ULONG_MAX ) continue;
      FD_TEST( cpu>1UL );
      for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
        if( !strcmp( topo->tiles[ j ].name, "genesi" ) || topo->tiles[ j ].cpu_idx!=(cpu^1UL) ) continue;
        int startup_pair = fd_topob_tile_priority_type( &topo->tiles[ i ] )==FD_TOPOB_PRIORITY_STARTUP ||
                           fd_topob_tile_priority_type( &topo->tiles[ j ] )==FD_TOPOB_PRIORITY_STARTUP;
        FD_TEST( startup_pair );
      }
    }
  }
}

/* "Nh" on the upper sibling of a pair covers the pair */
FD_UNIT_TEST( test_parse_affinity_upper_sibling ) {
  ulong sibling = fd_tile_private_sibling_idx( 0UL );
  if( sibling==ULONG_MAX ) return;
  char cstr[ 32 ];
  FD_TEST( fd_cstr_printf_check( cstr, sizeof(cstr), NULL, "%luh", sibling ) );
  ushort cpu[ FD_TILE_MAX ];
  FD_TEST( fd_topob_parse_affinity_cstr( cstr, cpu, 0, 0 )==2UL );
  FD_TEST( cpu[ 0 ]==(ushort)sibling && cpu[ 1 ]==0 );
  FD_TEST( fd_tile_private_cpus_parse( cstr, cpu )==2UL );
  FD_TEST( cpu[ 0 ]==(ushort)sibling && cpu[ 1 ]==0 );
}

static fd_topo_tile_t *
add_test_tile( fd_topo_t *  topo,
               char const * name,
               ulong        kind_id,
               ulong        cpu_idx ) {
  fd_topo_tile_t * tile = &topo->tiles[ topo->tile_cnt++ ];
  strncpy( tile->name, name, sizeof(tile->name) );
  tile->kind_id = kind_id;
  tile->cpu_idx = cpu_idx;
  return tile;
}

FD_UNIT_TEST( test_cpu_overlap_permitted ) {
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );

  add_test_tile( topo, "snapct", 0UL, 7UL );
  add_test_tile( topo, "execle", 0UL, 7UL );

  fd_topob_validate_cpu_overlaps( topo );
}

FD_UNIT_TEST( test_cpu_overlap_banned ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );

  if( pid==0 ) {
    fd_log_level_logfile_set( 6 );

    static fd_topo_t _topo[1];
    fd_topo_t * topo = _topo;
    fd_memset( topo, 0, sizeof(*topo) );

    add_test_tile( topo, "pack",  0UL, 9UL );
    add_test_tile( topo, "shred", 0UL, 9UL );

    fd_topob_validate_cpu_overlaps( topo );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( ( WIFEXITED( status ) && WEXITSTATUS( status )==1 ) ||
           ( WIFSIGNALED( status ) && WTERMSIG( status )==SIGABRT ) );
}

FD_UNIT_TEST( test_cpu_overlap_shared ) {
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );

  add_test_tile( topo, "pack",  0UL, 9UL )->floats = 1;
  add_test_tile( topo, "shred", 0UL, 9UL )->floats = 1;

  fd_topob_validate_cpu_overlaps( topo );
}

/* ---- Affinity string parsing ------------------------------------------- */

FD_UNIT_TEST( test_parse_affinity_shared ) {
  ushort cpu[ FD_TILE_MAX ];

  FD_TEST( fd_topob_parse_affinity_cstr( "0,s1,2-3,s4-6/2", cpu, 0, 1 )==6UL );
  FD_TEST( cpu[ 0 ]==0                       );
  FD_TEST( cpu[ 1 ]==(1|FD_TOPOB_CPU_SHARED) );
  FD_TEST( cpu[ 2 ]==2                       );
  FD_TEST( cpu[ 3 ]==3                       );
  FD_TEST( cpu[ 4 ]==(4|FD_TOPOB_CPU_SHARED) );
  FD_TEST( cpu[ 5 ]==(6|FD_TOPOB_CPU_SHARED) );

  /* a shared entry does not claim the cpu, so it may repeat */
  FD_TEST( fd_topob_parse_affinity_cstr( "s1,s1,f,s1", cpu, 0, 1 )==4UL );
  FD_TEST( cpu[ 2 ]==USHORT_MAX );
}

/* A malformed affinity string is a FD_LOG_ERR, so parse it in a child. */
static void
parse_affinity_topob_fails( char const * cstr,
                            int          allow_shared ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );

  if( pid==0 ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_core_set( 5 );

    ushort cpu[ FD_TILE_MAX ];
    fd_topob_parse_affinity_cstr( cstr, cpu, 0, allow_shared );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
}

static void
parse_affinity_tile_fails( char const * cstr ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );

  if( pid==0 ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_core_set( 5 );

    ushort cpu[ FD_TILE_MAX ];
    fd_tile_private_cpus_parse( cstr, cpu );
    _exit( 0 );
  }

  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
}

FD_UNIT_TEST( test_parse_affinity_malformed ) {
  parse_affinity_topob_fails( "s",   1 ); /* shared prefix with no cpu */
  parse_affinity_topob_fails( "1,s", 1 );
  parse_affinity_topob_fails( "s1-", 1 );
  parse_affinity_topob_fails( "s1",  0 ); /* caller cannot handle shared */
  parse_affinity_topob_fails( "1,1", 1 ); /* a plain repeat is still banned */
}

FD_UNIT_TEST( test_parse_affinity_bounds ) {
  {
    ushort cpu[ FD_TILE_MAX ];
    ulong cnt = fd_topob_parse_affinity_cstr( "1022-1023,f", cpu, 0, 1 );
    FD_TEST( cnt==3UL );
    FD_TEST( cpu[ 0 ]==1022 && cpu[ 1 ]==1023 && cpu[ 2 ]==USHORT_MAX );

    parse_affinity_topob_fails( "1024",                 1 );
    parse_affinity_topob_fails( "1023-1024",            1 );
    parse_affinity_topob_fails( "65536",                1 );
    parse_affinity_topob_fails( "18446744073709551614", 1 );
    parse_affinity_topob_fails( "18446744073709551615", 1 );
  }

  {
    ushort cpu[ FD_TILE_MAX ];
    ulong cnt = fd_tile_private_cpus_parse( "1022-1023,f", cpu );
    FD_TEST( cnt==3UL );
    FD_TEST( cpu[ 0 ]==1022 && cpu[ 1 ]==1023 && cpu[ 2 ]==USHORT_MAX );

    parse_affinity_tile_fails( "1024"                 );
    parse_affinity_tile_fails( "1023-1024"            );
    parse_affinity_tile_fails( "65536"                );
    parse_affinity_tile_fails( "18446744073709551614" );
    parse_affinity_tile_fails( "18446744073709551615" );
  }

  parse_affinity_topob_fails( "s65536", 1 );
}

/* ---- Tile object uses -------------------------------------------------- */

FD_UNIT_TEST( test_tile_uses_dedup ) {
  static fd_topo_tile_t tile[ 1 ];
  fd_topo_obj_t a = { .id = 7UL };
  fd_topo_obj_t b = { .id = 9UL };

  fd_topob_tile_uses( NULL, tile, &a, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( NULL, tile, &b, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( NULL, tile, &a, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FD_TEST( tile->uses_obj_cnt==2UL );
  FD_TEST( tile->uses_obj_mode[ 0 ]==FD_SHMEM_JOIN_MODE_READ_ONLY );

  /* A repeat never downgrades, and upgrades to read-write */
  fd_topob_tile_uses( NULL, tile, &b, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( NULL, tile, &a, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( tile->uses_obj_cnt==2UL );
  FD_TEST( tile->uses_obj_id[ 0 ]==7UL && tile->uses_obj_mode[ 0 ]==FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( tile->uses_obj_id[ 1 ]==9UL && tile->uses_obj_mode[ 1 ]==FD_SHMEM_JOIN_MODE_READ_WRITE );
}

/* --- genesi floats ------------------------------------------------------ */

/* Firedancer with snapshot load in efficient mode */
static tile_spec_t const FIREDANCER_SNAP_EFF_TILES[] = {
  { "netlnk", 1 }, { "metric", 1 }, { "diag",   1 }, { "genesi", 1 }, { "ipecho", 1 },
  { "admin",  1 }, { "waker",  1 }, { "mwaitx", 1 },
  { "net",    1 }, { "quic",   1 }, { "verify", 3 }, { "dedup",  1 }, { "resolv", 1 },
  { "pack",   1 }, { "execle", 2 }, { "poh",    1 }, { "shred",  1 }, { "sign",   1 },
  { "gui",    1 }, { "gossvf", 1 }, { "gossip", 1 }, { "repair", 1 }, { "replay", 1 },
  { "accdb",  1 }, { "execrp",10 }, { "txsend", 1 }, { "tower",  1 },
  { "snapct", 1 }, { "snapld", 1 }, { "snapdc", 3 }, { "snapin", 5 },
  { NULL, 0 }
};

/* genesi floats and is not counted as a startup tile: counting it made
   the L3 layout of an exact fit (38x2, 6 core L3) run out of cores. */
FD_UNIT_TEST( test_genesi_floats_l3_exact_fit ) {
  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 38, 6 );
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, FIREDANCER_SNAP_EFF_TILES );
  set_blocklist( topo, BLOCKLIST_0H( 38 ) );
  topo->sleep_obj_id = 0UL;
  fd_topob_auto_layout_cpus( topo, cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    int floating = fd_topob_tile_priority_type( tile )==FD_TOPOB_PRIORITY_FLOATING;
    FD_TEST( floating==( tile->cpu_idx==ULONG_MAX ) );
  }
  FD_TEST( topo->tiles[ fd_topo_find_tile( topo, "genesi", 0UL ) ].cpu_idx==ULONG_MAX );
}

/* Every class table row has exactly one phase */
FD_UNIT_TEST( test_tile_class_phase ) {
  char const * names[] = { "net", "snapin", "execrp", "genesi", "pack", "motor", "l4swap", "bogus" };
  uint const   exp  [] = { FD_TOPOB_TILE_ALWAYS, FD_TOPOB_TILE_STARTUP, FD_TOPOB_TILE_POSTSTART, FD_TOPOB_TILE_FLOATING,
                           FD_TOPOB_TILE_ALWAYS, FD_TOPOB_TILE_POSTSTART, FD_TOPOB_TILE_FLOATING, 0U };
  for( ulong i=0UL; i<sizeof(names)/sizeof(names[0]); i++ ) FD_TEST( ( fd_topob_tile_class( names[ i ] ) & FD_TOPOB_TILE_PHASE )==exp[ i ] );
  FD_TEST( fd_topob_tile_class( "pack"  ) & FD_TOPOB_TILE_SMT_CRITICAL );
  FD_TEST( fd_topob_tile_class( "poh"   ) & FD_TOPOB_TILE_SMT_CRITICAL );
  FD_TEST( fd_topob_tile_class( "motor" ) & FD_TOPOB_TILE_SMT_CRITICAL );
}

/* ---- isolcpus= ----------------------------------------------------------- */

/* Efficient mode never homes a floating tile on an isolated CPU;
   performance mode keeps today's placement */
FD_UNIT_TEST( test_isolated_floaters ) {
  ulong const iso[] = { 2UL, 50UL, 3UL, 51UL, 17UL, 65UL };
  for( ulong l3=0UL; l3<2UL; l3++ ) {
    for( int efficient=0; efficient<2; efficient++ ) {
      static fd_topo_t _topo[1];
      fd_topo_t * topo = _topo;
      fd_memset( topo, 0, sizeof(*topo) );
      make_tiles( topo, efficient ? FIREDANCER_EFF_TILES : FIREDANCER_TILES );
      set_blocklist( topo, BLOCKLIST_0H( 48 ) );
      topo->sleep_obj_id = efficient ? 0UL : ULONG_MAX;

      fd_topo_cpus_t cpus[1];
      make_cpus( cpus, 48, l3 ? 6UL : 0UL );
      fd_topob_auto_layout_cpus( topo, cpus );
      ulong before[ FD_TOPO_MAX_TILES ];
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) before[ i ] = topo->tiles[ i ].cpu_idx;

      for( ulong i=0UL; i<sizeof(iso)/sizeof(iso[0]); i++ ) cpus->cpu[ iso[ i ] ].isolated = 1;
      fd_topob_auto_layout_cpus( topo, cpus );
      ulong moved = 0UL;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        int pinned = !efficient || !!( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED );
        if( tile->cpu_idx<FD_TILE_MAX && !pinned ) FD_TEST( !cpus->cpu[ tile->cpu_idx ].isolated );
        if( !efficient ) FD_TEST( tile->cpu_idx==before[ i ] );
        moved += (ulong)( tile->cpu_idx!=before[ i ] );
      }
      if( efficient ) FD_TEST( moved ); /* net:1 and quic sat on 2 and 3 */
    }
  }
}

/* Pinned tiles take isolated CPUs first, leaving 0,1 for floaters */
FD_UNIT_TEST( test_isolated_pinned_first ) {
  static fd_topo_t topo[1];
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, (tile_spec_t const[]){ { "quic", 1 }, { "verify", 2 }, { "dedup", 1 }, { NULL, 0 } } );
  set_blocklist( topo, (ulong const[]){ ULONG_MAX } );
  topo->sleep_obj_id = 0UL;

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 4UL, 0UL );
  cpus->cpu[ 3 ].isolated = 1;
  cpus->cpu[ 7 ].isolated = 1;
  fd_topob_auto_layout_cpus( topo, cpus );
  FD_TEST( topo->tiles[ 0 ].cpu_idx==0UL && topo->tiles[ 3 ].cpu_idx==2UL );
  FD_TEST( topo->tiles[ 1 ].cpu_idx==3UL && topo->tiles[ 2 ].cpu_idx==1UL );
}

/* A hot floater skips an L3 domain whose free cores are all isolated */
FD_UNIT_TEST( test_isolated_l3_domain ) {
  static fd_topo_t topo[1];
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, (tile_spec_t const[]){ { "replay", 1 }, { "mlx5", 1 }, { NULL, 0 } } );
  set_blocklist( topo, (ulong const[]){ ULONG_MAX } );
  topo->sleep_obj_id = 0UL;

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 4UL, 2UL );
  for( ulong c=0UL; c<2UL; c++ ) { cpus->cpu[ c ].isolated = 1; cpus->cpu[ c+4UL ].isolated = 1; }
  fd_topob_auto_layout_cpus( topo, cpus );
  FD_TEST( topo->tiles[ 0 ].cpu_idx==0UL );
  FD_TEST( topo->tiles[ 1 ].cpu_idx==2UL );
}

/* Whole cores for floaters only count non-isolated ones: quic and
   dedup taking 0 and 1 with siblings left sign no CPU */
FD_UNIT_TEST( test_isolated_floaters_half_core ) {
  static fd_topo_t topo[1];
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, (tile_spec_t const[]){ { "quic", 1 }, { "dedup", 1 }, { "sign", 1 }, { NULL, 0 } } );
  set_blocklist( topo, (ulong const[]){ ULONG_MAX } );
  topo->sleep_obj_id = 0UL;

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 4UL, 0UL );
  ulong const iso[] = { 2UL, 3UL, 6UL, 7UL };
  for( ulong i=0UL; i<4UL; i++ ) cpus->cpu[ iso[ i ] ].isolated = 1;
  fd_topob_auto_layout_cpus( topo, cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) FD_TEST( !cpus->cpu[ topo->tiles[ i ].cpu_idx ].isolated );
  FD_TEST( topo->tiles[ 0 ].cpu_idx==0UL && topo->tiles[ 1 ].cpu_idx==4UL && topo->tiles[ 2 ].cpu_idx==1UL );
}

/* A hot pinned tile takes an isolated L3 core, leaving 0 to a floater */
FD_UNIT_TEST( test_isolated_l3_pinned_first ) {
  static fd_topo_t topo[1];
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, (tile_spec_t const[]){ { "replay", 1 }, { "mlx5", 1 }, { NULL, 0 } } );
  set_blocklist( topo, (ulong const[]){ ULONG_MAX } );
  topo->sleep_obj_id = 0UL;

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 4UL, 2UL );
  for( ulong c=1UL; c<4UL; c++ ) { cpus->cpu[ c ].isolated = 1; cpus->cpu[ c+4UL ].isolated = 1; }
  fd_topob_auto_layout_cpus( topo, cpus );
  FD_TEST( topo->tiles[ 0 ].cpu_idx==2UL ); /* L3 1 has the most isolated cores */
  FD_TEST( topo->tiles[ 1 ].cpu_idx==0UL );
}

/* Optional whole cores take an isolated half core first: execrp on
   1 with sibling 5 reserved would leave txsend no CPU */
FD_UNIT_TEST( test_isolated_dedicated_half_core ) {
  static fd_topo_t topo[1];
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, (tile_spec_t const[]){ { "quic", 1 }, { "verify", 1 }, { "dedup", 1 }, { "pack", 1 }, { "execrp", 1 }, { "txsend", 1 }, { NULL, 0 } } );
  set_blocklist( topo, (ulong const[]){ ULONG_MAX } );
  topo->sleep_obj_id = 0UL;

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 4UL, 0UL );
  ulong const iso[] = { 2UL, 3UL, 6UL, 7UL };
  for( ulong i=0UL; i<4UL; i++ ) cpus->cpu[ iso[ i ] ].isolated = 1;
  fd_topob_auto_layout_cpus( topo, cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    FD_TEST( tile->cpu_idx<cpus->cpu_cnt );
    if( !( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED ) ) FD_TEST( !cpus->cpu[ tile->cpu_idx ].isolated );
  }
  FD_TEST( topo->tiles[ 4 ].cpu_idx==6UL && topo->tiles[ 5 ].cpu_idx==1UL );
}

/* L3 packing needs non-isolated whole cores for its floaters: mlx5
   taking 0 and 4 would leave 1 and 5 for three floaters */
FD_UNIT_TEST( test_isolated_l3_floaters_half_core ) {
  static fd_topo_t topo[1];
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, (tile_spec_t const[]){ { "mlx5", 1 }, { "quic", 1 }, { "dedup", 1 }, { "sign", 1 }, { NULL, 0 } } );
  set_blocklist( topo, (ulong const[]){ ULONG_MAX } );
  topo->sleep_obj_id = 0UL;

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, 4UL, 2UL );
  ulong const iso[] = { 2UL, 3UL, 6UL, 7UL };
  for( ulong i=0UL; i<4UL; i++ ) cpus->cpu[ iso[ i ] ].isolated = 1;
  fd_topob_auto_layout_cpus( topo, cpus );
  ulong const expected[] = { 0UL, 4UL, 1UL, 5UL };
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) FD_TEST( topo->tiles[ i ].cpu_idx==expected[ i ] );
}

/* Lay out tiles in efficient mode on physical_cores x 2 with the
   listed CPUs isolated and check each tile's CPU.  iso[] and
   blocklist[] are ULONG_MAX terminated, expected[] is per tile. */
static void
layout_isolated( ulong               physical_cores,
                 ulong               l3_cores,
                 ulong const *       iso,
                 ulong const *       blocklist,
                 tile_spec_t const * tiles,
                 ulong const *       expected ) {
  static fd_topo_t topo[1];
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, tiles );
  set_blocklist( topo, blocklist );
  topo->sleep_obj_id = 0UL;

  fd_topo_cpus_t cpus[1];
  make_cpus( cpus, physical_cores, l3_cores );
  for( ulong const * p = iso; *p!=ULONG_MAX; p++ ) cpus->cpu[ *p ].isolated = 1;
  fd_topob_auto_layout_cpus( topo, cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( topo->tiles[ i ].cpu_idx!=expected[ i ] ) FD_LOG_ERR(( "tile %s:%lu on cpu %lu, expected %lu", topo->tiles[ i ].name, topo->tiles[ i ].kind_id, topo->tiles[ i ].cpu_idx, expected[ i ] ));
  }
}

/* Whole cores are planned before isolated CPUs are handed out: verify
   taking isolated 3 and pack the non-isolated core 1/5 left txsend no
   CPU though isolated 7 was free */
FD_UNIT_TEST( test_isolated_plan_whole_cores ) {
  layout_isolated( 4, 0, (ulong const[]){ 3, 7, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "quic", 1 }, { "verify", 1 }, { "dedup", 1 }, { "pack", 1 }, { "sign", 1 }, { "shred", 1 }, { "txsend", 1 }, { NULL, 0 } },
                   (ulong const[]){ 0, 4, 1, 3, 5, 2, 6 } );
}

/* Inputs where taking the first isolated or whole core starved a later
   tile, or a pinned tile took the all-isolated core pack wanted */
FD_UNIT_TEST( test_isolated_plan_fits ) {
  layout_isolated( 5, 0, (ulong const[]){ 1, 2, 3, 4, 6, ULONG_MAX }, (ulong const[]){ 0, 5, ULONG_MAX },
                   (tile_spec_t const[]){ { "shred", 1 }, { "txsend", 1 }, { "execle", 1 }, { "execrp", 1 }, { "gossip", 1 }, { NULL, 0 } },
                   (ulong const[]){ 7, 9, 1, 6, 8 } );
  layout_isolated( 3, 0, (ulong const[]){ 1, 2, ULONG_MAX }, (ulong const[]){ 0, 3, ULONG_MAX },
                   (tile_spec_t const[]){ { "sign", 1 }, { "txsend", 1 }, { "execrp", 1 }, { NULL, 0 } },
                   (ulong const[]){ 4, 5, 1 } );
  layout_isolated( 3, 2, (ulong const[]){ 0, 1, 2, 4, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "pack", 1 }, { "txsend", 1 }, { "tower", 1 }, { NULL, 0 } },
                   (ulong const[]){ 1, 5, 3 } );
  layout_isolated( 3, 2, (ulong const[]){ 0, 1, 2, 5, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "shred", 1 }, { "txsend", 1 }, { "execrp", 1 }, { NULL, 0 } },
                   (ulong const[]){ 3, 4, 2 } );
  layout_isolated( 3, 0, (ulong const[]){ 0, 1, 2, 5, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "pack", 1 }, { "shred", 1 }, { "mlx5", 1 }, { NULL, 0 } },
                   (ulong const[]){ 2, 4, 3 } );
  layout_isolated( 3, 2, (ulong const[]){ 0, 1, 2, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "txsend", 1 }, { "execrp", 1 }, { "mlx5", 1 }, { "tower", 1 }, { NULL, 0 } },
                   (ulong const[]){ 5, 0, 3, 4 } );
  layout_isolated( 3, 2, (ulong const[]){ 0, 1, 3, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "verify", 1 }, { "resolv", 1 }, { "pack", 1 }, { "sign", 1 }, { NULL, 0 } },
                   (ulong const[]){ 1, 4, 0, 2 } );
  layout_isolated( 4, 0, (ulong const[]){ 1, 2, 7, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "verify", 3 }, { "dedup", 1 }, { "pack", 1 }, { NULL, 0 } },
                   (ulong const[]){ 1, 2, 7, 5, 0 } );
  layout_isolated( 2, 1, (ulong const[]){ 0, 2, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "verify", 1 }, { "dedup", 1 }, { "pack", 1 }, { NULL, 0 } },
                   (ulong const[]){ 1, 3, 0 } );
  layout_isolated( 2, 1, (ulong const[]){ 1, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "verify", 1 }, { "dedup", 1 }, { "pack", 1 }, { NULL, 0 } },
                   (ulong const[]){ 1, 3, 0 } );
  layout_isolated( 5, 0, (ulong const[]){ 1, 2, 3, 4, 8, 9, ULONG_MAX }, (ulong const[]){ 0, 5, ULONG_MAX },
                   (tile_spec_t const[]){ { "pack", 1 }, { "sign", 1 }, { "mlx5", 1 }, { NULL, 0 } },
                   (ulong const[]){ 3, 7, 6 } );
  layout_isolated( 5, 3, (ulong const[]){ 1, 2, 3, 6, ULONG_MAX }, (ulong const[]){ 0, 5, ULONG_MAX },
                   (tile_spec_t const[]){ { "quic", 1 }, { "verify", 1 }, { "resolv", 1 }, { "pack", 1 }, { "sign", 1 }, { NULL, 0 } },
                   (ulong const[]){ 7, 2, 8, 1, 4 } );
  layout_isolated( 6, 3, (ulong const[]){ 0, 1, 4, 5, 6, 8, 11, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "quic", 1 }, { "verify", 1 }, { "resolv", 1 }, { "pack", 1 }, { "sign", 1 }, { "mlx5", 1 }, { "gossip", 1 }, { NULL, 0 } },
                   (ulong const[]){ 2, 0, 3, 5, 9, 7, 10 } );
  layout_isolated( 6, 3, (ulong const[]){ 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, ULONG_MAX }, (ulong const[]){ ULONG_MAX },
                   (tile_spec_t const[]){ { "quic", 1 }, { "pack", 1 }, { "gossip", 1 }, { NULL, 0 } },
                   (ulong const[]){ 0, 2, 7 } );
}

/* ---- Launcher sets for unpinned tiles ----------------------------------- */

static ulong
floating_set_tile( fd_topo_t *  topo,
                   char const * name,
                   ulong        cpu_idx,
                   int          floats ) {
  fd_topo_tile_t * tile = &topo->tiles[ topo->tile_cnt ];
  fd_memset( tile, 0, sizeof(*tile) );
  fd_cstr_ncpy( tile->name, name, sizeof(tile->name) );
  tile->id      = topo->tile_cnt;
  tile->cpu_idx = cpu_idx;
  tile->floats  = floats;
  return topo->tile_cnt++;
}

FD_UNIT_TEST( test_cpus_floating ) {
  static fd_topo_t topo[1];
  fd_topo_cpus_t cpus[1];
  FD_CPUSET_DECL( launch );
  FD_CPUSET_DECL( float_set );
  FD_CPUSET_DECL( cpuless );

  /* Performance mode, 8x2: pinned 1,2 and their siblings 9,10 are
     claimed; the rest of the launch mask is used */
  make_cpus( cpus, 8UL, 0UL );
  fd_memset( topo, 0, sizeof(*topo) );
  floating_set_tile( topo, "pack",   1UL,       0 );
  floating_set_tile( topo, "verify", 2UL,       0 );
  floating_set_tile( topo, "metric", ULONG_MAX, 0 );
  fd_cpuset_new( launch ); for( ulong c=0UL; c<16UL; c++ ) fd_cpuset_insert( launch, c );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( !fd_cpuset_cnt( float_set ) );
  FD_TEST( fd_cpuset_cnt( cpuless )==12UL );
  FD_TEST( !fd_cpuset_test( cpuless, 1UL ) && !fd_cpuset_test( cpuless, 9UL ) );
  FD_TEST( !fd_cpuset_test( cpuless, 2UL ) && !fd_cpuset_test( cpuless, 10UL ) );
  FD_TEST(  fd_cpuset_test( cpuless, 0UL ) &&  fd_cpuset_test( cpuless, 8UL ) );

  /* Restricted launch mask: never widened */
  fd_cpuset_new( launch ); fd_cpuset_insert( launch, 0UL ); fd_cpuset_insert( launch, 9UL );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_cnt( cpuless )==1UL && fd_cpuset_test( cpuless, 0UL ) );

  /* Everything in the launch mask claimed: today's fallback */
  fd_cpuset_new( launch ); fd_cpuset_insert( launch, 1UL ); fd_cpuset_insert( launch, 9UL );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_eq( cpuless, launch ) );

  /* Isolated CPUs are skipped, unless only they are left */
  cpus->cpu[ 5 ].isolated = 1; cpus->cpu[ 13 ].isolated = 1;
  fd_cpuset_new( launch ); for( ulong c=0UL; c<16UL; c++ ) fd_cpuset_insert( launch, c );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_cnt( cpuless )==10UL );
  FD_TEST( !fd_cpuset_test( cpuless, 5UL ) && !fd_cpuset_test( cpuless, 13UL ) );
  fd_cpuset_new( launch ); fd_cpuset_insert( launch, 1UL ); fd_cpuset_insert( launch, 5UL ); fd_cpuset_insert( launch, 9UL );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_eq( cpuless, launch ) );
  cpus->cpu[ 5 ].isolated = 0; cpus->cpu[ 13 ].isolated = 0;

  /* Efficient mode: floats tiles share 3,4; cpuless tiles use them
     when the launch mask overlaps */
  floating_set_tile( topo, "quic",   3UL, 1 );
  floating_set_tile( topo, "gossip", 4UL, 1 );
  fd_cpuset_new( launch ); for( ulong c=0UL; c<16UL; c++ ) fd_cpuset_insert( launch, c );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_cnt( float_set )==2UL && fd_cpuset_test( float_set, 3UL ) && fd_cpuset_test( float_set, 4UL ) );
  FD_TEST( fd_cpuset_eq( cpuless, float_set ) );
  cpus->cpu[ 4 ].isolated = 1;
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_cnt( cpuless )==1UL && fd_cpuset_test( cpuless, 3UL ) );
  cpus->cpu[ 4 ].isolated = 0;

  /* Efficient mode with a partition: the launch mask excludes the
     float CPUs, so cpuless tiles avoid pinned, siblings and float CPUs */
  fd_cpuset_new( launch );
  for( ulong c=0UL; c<16UL; c++ ) if( c!=1UL && c!=2UL && c!=3UL && c!=4UL && c!=9UL ) fd_cpuset_insert( launch, c );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_cnt( cpuless )==10UL );
  FD_TEST( !fd_cpuset_test( cpuless, 10UL ) );
  FD_TEST(  fd_cpuset_test( cpuless, 11UL ) && fd_cpuset_test( cpuless, 12UL ) ); /* floats tiles' siblings stay usable */

  /* A floats tile sharing a pinned tile's sibling loses that CPU */
  floating_set_tile( topo, "diag", 9UL, 1 );
  fd_cpuset_new( launch ); for( ulong c=0UL; c<16UL; c++ ) fd_cpuset_insert( launch, c );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( !fd_cpuset_test( float_set, 9UL ) );

  /* SMT off: no siblings to claim */
  make_cpus( cpus, 8UL, 0UL );
  for( ulong c=8UL; c<16UL; c++ ) { cpus->cpu[ c ].online = 0; cpus->cpu[ c ].sibling = ULONG_MAX; }
  for( ulong c=0UL; c<8UL;  c++ ) cpus->cpu[ c ].sibling = ULONG_MAX;
  fd_memset( topo, 0, sizeof(*topo) );
  floating_set_tile( topo, "pack",   1UL,       0 );
  floating_set_tile( topo, "metric", ULONG_MAX, 0 );
  fd_cpuset_new( launch ); for( ulong c=0UL; c<8UL; c++ ) fd_cpuset_insert( launch, c );
  fd_topo_cpus_floating( cpus, topo, launch, float_set, cpuless );
  FD_TEST( fd_cpuset_cnt( cpuless )==7UL && !fd_cpuset_test( cpuless, 1UL ) );
}

/* ======================================================================== */

/* ---- Fleet shaped hosts ------------------------------------------------ */

#define SMT_ON       (0)
#define SMT_ABSENT   (1) /* BIOS off, no siblings */
#define SMT_RUNTIME  (2) /* smt/control=off, siblings present but offline */
#define SMT_ADJACENT (3) /* sibling of cpu i is i^1 */

/* Builds sockets x phys cores, numa_per_socket NUMA nodes per socket,
   cores_per_l3 cores per L3 (0: unknown), siblings at i+N or i^1 the
   way fd_topo_cpus_init reports them, then takes offline[] (ULONG_MAX
   terminated, NULL for none) offline. */
static void
make_cpus_shape( fd_topo_cpus_t * cpus,
                 ulong            sockets,
                 ulong            numa_per_socket,
                 ulong            phys,
                 ulong            cores_per_l3,
                 int              smt,
                 ulong const *    offline ) {
  ulong n     = sockets*phys;
  ulong per   = phys/numa_per_socket;
  ulong l3_ps = cores_per_l3 ? (phys+cores_per_l3-1UL)/cores_per_l3 : 0UL;
  fd_memset( cpus, 0, sizeof(*cpus) );
  cpus->numa_node_cnt = sockets*numa_per_socket;
  cpus->l3_cnt        = sockets*l3_ps;
  cpus->cpu_cnt       = smt==SMT_ABSENT ? n : 2UL*n;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    ulong core = smt==SMT_ADJACENT ? i/2UL : i%n;
    ulong sock = core/phys;
    ulong loc  = core%phys;
    fd_topo_cpu_t * cpu = &cpus->cpu[ i ];
    cpu->idx       = i;
    cpu->online    = 1;
    cpu->numa_node = sock*numa_per_socket + fd_ulong_min( loc/per, numa_per_socket-1UL );
    cpu->die_idx   = sock;
    cpu->l3_idx    = cores_per_l3 ? sock*l3_ps + loc/cores_per_l3 : ULONG_MAX;
    cpu->sibling   = smt==SMT_ABSENT ? ULONG_MAX : smt==SMT_ADJACENT ? i^1UL : ( i<n ? i+n : i-n );
  }
  if( smt==SMT_RUNTIME ) {
    for( ulong i=n; i<2UL*n; i++ ) {
      cpus->cpu[ i-n ].sibling = ULONG_MAX;
      cpus->cpu[ i   ].online  = 0;
      cpus->cpu[ i   ].sibling = ULONG_MAX;
      cpus->cpu[ i   ].l3_idx  = ULONG_MAX;
    }
  }
  make_cpus_offline( cpus, offline );
}

/* Default Firedancer topology with snapshots, rpc, telemetry and
   bundles (mainnet configuration), and its Alpenglow variant. */

static tile_spec_t const MAINNET_TILES[] = {
  { "netlnk", 1 }, { "net",    2 }, { "metric", 1 }, { "diag",   1 },
  { "snapct", 1 }, { "snapld", 1 }, { "snapdc", 3 }, { "snapin", 5 },
  { "genesi", 1 }, { "ipecho", 1 }, { "gossvf", 1 }, { "gossip", 1 },
  { "shred",  1 }, { "repair", 1 }, { "rserve", 1 }, { "replay", 1 },
  { "accdb",  1 }, { "execrp",10 }, { "tower",  1 }, { "txsend", 1 },
  { "quic",   1 }, { "verify", 3 }, { "dedup",  1 }, { "resolv", 1 },
  { "pack",   1 }, { "execle", 2 }, { "poh",    1 }, { "sign",   2 },
  { "rpc",    1 }, { "admin",  1 }, { "event",  1 }, { "bundle", 1 },
  { "gui",    1 },
  { NULL, 0 }
};

static tile_spec_t const MAINNET_AG_TILES[] = {
  { "netlnk", 1 }, { "net",    2 }, { "metric", 1 }, { "diag",   1 },
  { "snapct", 1 }, { "snapld", 1 }, { "snapdc", 3 }, { "snapin", 5 },
  { "genesi", 1 }, { "ipecho", 1 }, { "gossvf", 1 }, { "gossip", 1 },
  { "shred",  1 }, { "rotor",  1 }, { "rserve", 1 }, { "replay", 1 },
  { "accdb",  1 }, { "execrp",10 }, { "votor",  1 }, { "tower",  1 },
  { "quic",   1 }, { "verify", 3 }, { "dedup",  1 }, { "resolv", 1 },
  { "pack",   1 }, { "execle", 2 }, { "motor",  1 }, { "sign",   2 },
  { "rpc",    1 }, { "admin",  1 }, { "event",  1 }, { "bundle", 1 },
  { "gui",    1 },
  { NULL, 0 }
};

/* Operator sizing still seen on small boxes */
static tile_spec_t const MAINNET_WIDE_TILES[] = {
  { "netlnk", 1 }, { "net",    2 }, { "metric", 1 }, { "diag",   1 },
  { "snapct", 1 }, { "snapld", 1 }, { "snapdc", 3 }, { "snapin", 5 },
  { "genesi", 1 }, { "ipecho", 1 }, { "gossvf", 2 }, { "gossip", 1 },
  { "shred",  1 }, { "repair", 1 }, { "rserve", 1 }, { "replay", 1 },
  { "accdb",  1 }, { "execrp",10 }, { "tower",  1 }, { "txsend", 1 },
  { "quic",   1 }, { "verify", 6 }, { "dedup",  1 }, { "resolv", 1 },
  { "pack",   1 }, { "execle", 2 }, { "poh",    1 }, { "sign",   2 },
  { "rpc",    1 }, { "admin",  1 }, { "event",  1 }, { "bundle", 1 },
  { "gui",    1 },
  { NULL, 0 }
};

static int
name_in( char const *         name,
         char const * const * names ) {
  for( char const * const * p = names; *p; p++ ) if( !strcmp( name, *p ) ) return 1;
  return 0;
}

/* Layout invariants that hold on every host shape.  steady counts
   ALWAYS and POST_START tiles, the deliberate STARTUP overlap aside. */
static void
check_layout_invariants( fd_topo_t const *      topo,
                         fd_topo_cpus_t const * cpus,
                         int                    efficient,
                         ulong                  execrp_whole_min ) {
  fd_topob_validate_cpu_overlaps( topo );

  uchar steady[ FD_TILE_MAX ] = {0};
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    ulong cpu = tile->cpu_idx;
    int floating = fd_topob_tile_priority_type( tile )==FD_TOPOB_PRIORITY_FLOATING;
    FD_TEST( floating==( cpu==ULONG_MAX ) );
    if( floating ) continue;
    FD_TEST( cpu<cpus->cpu_cnt );
    FD_TEST( cpus->cpu[ cpu ].online );
    for( ulong b=0UL; b<topo->blocklist_cores_cnt; b++ ) FD_TEST( topo->blocklist_cores_cpu_idx[ b ]!=cpu );
    if( !( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_STARTUP ) ) steady[ cpu ]++;
  }

  /* Critical siblings empty, execrp:0..k whole and ahead of shared ones */
  ulong execrp_whole  = 0UL;
  ulong execrp_shared = ULONG_MAX;
  ulong execrp_last   = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( tile->cpu_idx==ULONG_MAX || ( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_STARTUP ) ) continue;
    ulong s     = cpus->cpu[ tile->cpu_idx ].sibling;
    int   whole = s==ULONG_MAX || !steady[ s ];
    if( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_SMT_CRITICAL ) FD_TEST( whole );
    if( strcmp( tile->name, "execrp" ) ) continue;
    if( whole ) { execrp_whole++; execrp_last = fd_ulong_max( execrp_last, tile->kind_id ); }
    else          execrp_shared = fd_ulong_min( execrp_shared, tile->kind_id );
  }
  FD_TEST( execrp_shared==ULONG_MAX || execrp_last<execrp_shared || !execrp_whole );
  FD_TEST( execrp_whole>=execrp_whole_min );

  /* No idle whole core while any steady core is shared.  Efficient mode
     floats most tiles, and multi-NUMA hosts may keep a node free. */
  if( efficient || cpus->numa_node_cnt>1UL ) return;
  int shared = 0, idle = 0;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    ulong s = cpus->cpu[ i ].sibling;
    if( s==ULONG_MAX || s<i ) continue;
    shared |= steady[ i ] && steady[ s ];
    int usable = cpus->cpu[ i ].online && cpus->cpu[ s ].online;
    for( ulong b=0UL; b<topo->blocklist_cores_cnt; b++ ) usable &= topo->blocklist_cores_cpu_idx[ b ]!=i && topo->blocklist_cores_cpu_idx[ b ]!=s;
    idle |= usable && !steady[ i ] && !steady[ s ];
  }
  FD_TEST( !( shared && idle ) );
}

/* Performance mode with a cache topology keeps poh, accdb and the
   lowest execle in pack's L3, spilling only the highest execle */
static void
check_group_l3( fd_topo_t const *      topo,
                fd_topo_cpus_t const * cpus ) {
  ulong pack = fd_topo_find_tile( topo, "pack", 0UL );
  FD_TEST( pack!=ULONG_MAX );
  ulong l3 = cpus->cpu[ topo->tiles[ pack ].cpu_idx ].l3_idx;
  ulong spill = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( !name_in( tile->name, (char const *[]){ "poh", "motor", "accdb", "execle", NULL } ) ) continue;
    int in = cpus->cpu[ tile->cpu_idx ].l3_idx==l3;
    if( strcmp( tile->name, "execle" ) ) FD_TEST( in );
    else if( !in ) spill++;
    else           FD_TEST( !spill );
  }
}

/* Whole core execrp count of the dedicated budget on main */
static ulong
main_execrp_whole( fd_topo_cpus_t const * cpus,
                   fd_topo_t const *      topo ) {
  ulong free_logical = 0UL, need = 0UL, critical = 0UL, startup = 0UL, post = 0UL, execrp = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    int blocked = !cpus->cpu[ i ].online;
    for( ulong b=0UL; b<topo->blocklist_cores_cnt; b++ ) blocked |= topo->blocklist_cores_cpu_idx[ b ]==i;
    free_logical += (ulong)!blocked;
  }
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    uint cls = fd_topob_tile_class( tile->name );
    if( fd_topob_tile_priority_type( tile )==FD_TOPOB_PRIORITY_FLOATING ) continue;
    need     += (ulong)!!( cls & FD_TOPOB_TILE_ALWAYS );
    startup  += (ulong)!!( cls & FD_TOPOB_TILE_STARTUP );
    post     += (ulong)!!( cls & FD_TOPOB_TILE_POSTSTART );
    critical += (ulong)!!( cls & FD_TOPOB_TILE_SMT_CRITICAL );
    execrp   += (ulong)!strcmp( tile->name, "execrp" );
  }
  need += fd_ulong_max( startup, post );
  return fd_ulong_min( execrp, fd_ulong_sat_sub( free_logical, need+critical ) );
}

static void
layout_shape( fd_topo_cpus_t const * shape,
              tile_spec_t const *    tiles,
              ulong const *          blocklist,
              int                    efficient ) {
  static fd_topo_cpus_t cpus[1];
  *cpus = *shape;
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, tiles );
  set_blocklist( topo, blocklist );
  topo->sleep_obj_id = efficient ? 0UL : ULONG_MAX;
  fd_topob_auto_layout_cpus( topo, cpus );

  /* SMT hosts short of whole cores keep at least main's whole execrp */
  ulong p2 = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) p2 += (ulong)( cpus->cpu[ i ].sibling!=ULONG_MAX && cpus->cpu[ i ].sibling>i );
  ulong execrp_min = !efficient && p2 && cpus->numa_node_cnt==1UL ? fd_ulong_min( main_execrp_whole( cpus, topo ), 10UL ) : 0UL;
  check_layout_invariants( topo, cpus, efficient, execrp_min );
  if( !efficient && fd_topo_cpus_l3_complete( cpus ) ) check_group_l3( topo, cpus );
}

static int
layout_shape_ok( fd_topo_cpus_t const * shape,
                 tile_spec_t const *    tiles,
                 ulong const *          blocklist,
                 int                    efficient ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( pid==0 ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_stderr_set( 6 );
    fd_log_level_core_set( 5 );
    layout_shape( shape, tiles, blocklist, efficient );
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  return !WEXITSTATUS( status );
}

FD_UNIT_TEST( test_fleet_shapes ) {
  /* sockets, numa/socket, phys/socket, cores/L3, smt, offline, too small for mainnet */
  static ulong const OFF_9375F[] = { 5, 37, 40, ULONG_MAX };
  static struct { ulong s, nps, phys, ccd; int smt; ulong const * off; int small; } const SHAPE[] = {
    { 1, 1, 128, 8, SMT_ON,       NULL,      0 }, /* 9754                  */
    { 1, 1,  64, 8, SMT_ON,       NULL,      0 }, /* 9575F / 9554P         */
    { 1, 1,  64, 8, SMT_ABSENT,   NULL,      0 },
    { 1, 1,  48, 6, SMT_ON,       NULL,      0 }, /* 9474F                 */
    { 1, 2,  48, 6, SMT_ON,       NULL,      0 }, /* 9474F NPS2            */
    { 1, 4,  32, 4, SMT_ON,       NULL,      0 }, /* 9354 NPS4             */
    { 1, 1,  32, 4, SMT_ON,       NULL,      0 }, /* 9354P / 7543P         */
    { 1, 1,  32, 4, SMT_ABSENT,   NULL,      1 }, /* 7543P SMT off         */
    { 1, 1,  32, 4, SMT_RUNTIME,  NULL,      1 },
    { 1, 1,  32, 4, SMT_ON,       OFF_9375F, 0 }, /* 9375F, 61 online      */
    { 1, 1,  24, 3, SMT_ON,       NULL,      0 }, /* 9275F                 */
    { 1, 1,  24, 6, SMT_ON,       NULL,      0 }, /* 7443P                 */
    { 1, 1,  24, 4, SMT_ON,       NULL,      0 }, /* 9254                  */
    { 1, 1,  16, 8, SMT_ON,       NULL,      1 }, /* 9950X                 */
    { 2, 1,  32,32, SMT_ON,       NULL,      0 }, /* Xeon 8462Y+ 2S        */
    { 1, 1,  24, 6, SMT_ADJACENT, NULL,      0 }, /* VM, adjacent siblings */
  };
  tile_spec_t const * const TILES[] = { MAINNET_TILES, MAINNET_AG_TILES, MAINNET_WIDE_TILES, FIREDANCER_TILES, FD_FEWER_TILES };
  for( ulong i=0UL; i<sizeof(SHAPE)/sizeof(SHAPE[0]); i++ ) {
    for( ulong l3=0UL; l3<2UL; l3++ ) {
      static fd_topo_cpus_t cpus[1];
      make_cpus_shape( cpus, SHAPE[ i ].s, SHAPE[ i ].nps, SHAPE[ i ].phys, l3 ? 0UL : SHAPE[ i ].ccd, SHAPE[ i ].smt, SHAPE[ i ].off );
      ulong bl[ 3 ] = { 0UL, cpus->cpu[ 0 ].sibling!=ULONG_MAX ? cpus->cpu[ 0 ].sibling : ULONG_MAX, ULONG_MAX };
      for( ulong t=0UL; t<sizeof(TILES)/sizeof(TILES[0]); t++ ) {
        for( int efficient=0; efficient<2; efficient++ ) {
          int ok = layout_shape_ok( cpus, TILES[ t ], bl, efficient );
          if( FD_UNLIKELY( !ok && ( !SHAPE[ i ].small || TILES[ t ]==FD_FEWER_TILES ) ) ) FD_LOG_ERR(( "shape %lu l3 %lu tiles %lu efficient %d failed", i, l3, t, efficient ));
        }
      }
    }
  }
}

/* 20..48 physical cores x verify {3,6}, without and with 6 core L3s:
   graded pairing keeps every invariant and never shrinks the boot
   envelope of main */
FD_UNIT_TEST( test_smt_budget_sweep ) {
  for( ulong l3=0UL; l3<=6UL; l3+=6UL ) {
    for( ulong n=20UL; n<=48UL; n++ ) {
      static fd_topo_cpus_t cpus[1];
      make_cpus_shape( cpus, 1UL, 1UL, n, l3, SMT_ON, NULL );
      ulong bl[ 3 ] = { 0UL, n, ULONG_MAX };
      /* main boots default counts from 21 cores, the wide ones from 23 */
      int ok_main = layout_shape_ok( cpus, MAINNET_TILES,      bl, 0 );
      int ok_wide = layout_shape_ok( cpus, MAINNET_WIDE_TILES, bl, 0 );
      FD_TEST( ok_main || n<21UL );
      FD_TEST( ok_wide || n<23UL );
      FD_TEST( layout_shape_ok( cpus, FIREDANCER_TILES,   bl, 0 ) );
    }
  }
}

/* CI bench on a 9474F (8 L3 of 6 cores): pack, motor, accdb and
   execle:0-5 paired in one L3, execle:6-7 paired in the next */
FD_UNIT_TEST( test_group_l3_bench_9474f ) {
  static tile_spec_t const BENCH_TILES[] = {
    { "netlnk", 1 }, { "net",    2 }, { "metric", 1 }, { "diag",   1 }, { "genesi", 1 }, { "ipecho", 1 },
    { "gossvf", 1 }, { "gossip", 1 }, { "shred",  1 }, { "rotor",  1 }, { "rserve", 1 }, { "replay", 1 },
    { "accdb",  1 }, { "execrp", 1 }, { "votor",  1 }, { "quic",   2 }, { "verify",32 }, { "dedup",  1 },
    { "resolv", 1 }, { "pack",   1 }, { "execle", 8 }, { "motor",  1 }, { "sign",   2 }, { "rpc",    1 },
    { "admin",  1 }, { "waker",  1 }, { "bencho", 1 }, { "benchg",16 }, { "benchs", 4 }, { NULL, 0 }
  };
  for( ulong v=0UL; v<2UL; v++ ) {
    static fd_topo_cpus_t cpus[1];
    make_cpus_shape( cpus, 1UL, 1UL, 48UL, v ? 4UL : 6UL, SMT_ON, NULL );
    static fd_topo_t _topo[1];
    fd_topo_t * topo = _topo;
    fd_memset( topo, 0, sizeof(*topo) );
    make_tiles( topo, BENCH_TILES );
    set_blocklist( topo, BLOCKLIST_0H( 48 ) );
    topo->sleep_obj_id = ULONG_MAX;
    fd_topob_auto_layout_cpus( topo, cpus );
    check_layout_invariants( topo, cpus, 0, 0UL );
    check_group_l3( topo, cpus );

    /* 4 core L3s (v=1) hold pack, motor, accdb and execle:0-1 */
    ulong l3 = cpus->cpu[ topo->tiles[ fd_topo_find_tile( topo, "pack", 0UL ) ].cpu_idx ].l3_idx;
    for( ulong k=0UL; k<8UL; k++ ) {
      ulong c = topo->tiles[ fd_topo_find_tile( topo, "execle", k ) ].cpu_idx;
      FD_TEST( cpus->cpu[ c ].l3_idx==l3+( k>=( v ? 2UL : 6UL ) ) );
      FD_TEST( topo->tiles[ fd_topo_find_tile( topo, "execle", k^1UL ) ].cpu_idx==cpus->cpu[ c ].sibling );
    }
  }
}

/* 32x2 efficient with isolcpus=16-31,48-63 boots like on main: the
   graded plan would strand the floaters, the sequential layout keeps
   them off isolated CPUs */
FD_UNIT_TEST( test_smt_budget_efficient_isolcpus ) {
  static tile_spec_t const MAINNET_EFF_TILES[] = {
    { "netlnk", 1 }, { "net",    2 }, { "metric", 1 }, { "diag",   1 }, { "waker",  1 }, { "mwaitx", 1 },
    { "snapct", 1 }, { "snapld", 1 }, { "snapdc", 3 }, { "snapin", 5 }, { "genesi", 1 }, { "ipecho", 1 },
    { "gossvf", 1 }, { "gossip", 1 }, { "shred",  1 }, { "repair", 1 }, { "rserve", 1 }, { "replay", 1 },
    { "accdb",  1 }, { "execrp",10 }, { "tower",  1 }, { "txsend", 1 }, { "quic",   1 }, { "verify", 3 },
    { "dedup",  1 }, { "resolv", 1 }, { "pack",   1 }, { "execle", 2 }, { "poh",    1 }, { "sign",   2 },
    { "rpc",    1 }, { "admin",  1 }, { "event",  1 }, { "bundle", 1 }, { "gui",    1 }, { NULL, 0 }
  };
  static fd_topo_cpus_t cpus[1];
  make_cpus_shape( cpus, 1UL, 1UL, 32UL, 16UL, SMT_ON, NULL );
  for( ulong i=16UL; i<32UL; i++ ) { cpus->cpu[ i ].isolated = 1; cpus->cpu[ i+32UL ].isolated = 1; }
  FD_TEST( layout_shape_ok( cpus, MAINNET_EFF_TILES, BLOCKLIST_0H( 32 ), 1 ) );
}

/* 24x2 mainnet: replay, tower, shred:0, net:0 and accdb get a cold
   sibling or none, no two different AVX heavy kinds share, and 7
   execrp stay whole like on main */
FD_UNIT_TEST( test_smt_budget_24x2_partners ) {
  static fd_topo_cpus_t cpus[1];
  make_cpus_shape( cpus, 1UL, 1UL, 24UL, 0UL, SMT_ON, NULL );
  static fd_topo_t _topo[1];
  fd_topo_t * topo = _topo;
  fd_memset( topo, 0, sizeof(*topo) );
  make_tiles( topo, MAINNET_TILES );
  set_blocklist( topo, BLOCKLIST_0H( 24 ) );
  topo->sleep_obj_id = ULONG_MAX;
  fd_topob_auto_layout_cpus( topo, cpus );
  check_layout_invariants( topo, cpus, 0, 7UL );

  char const * cold[] = { "gui", "rpc", "event", "rserve", "gossip", "gossvf", "sign", NULL };
  char const * avx [] = { "verify", "sign", "shred", NULL };
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * a = &topo->tiles[ i ];
    if( a->cpu_idx==ULONG_MAX || fd_topob_tile_priority_type( a )==FD_TOPOB_PRIORITY_STARTUP ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t const * b = &topo->tiles[ j ];
      if( j==i || b->cpu_idx!=cpus->cpu[ a->cpu_idx ].sibling || fd_topob_tile_priority_type( b )==FD_TOPOB_PRIORITY_STARTUP ) continue;
      int protect   = !strcmp( a->name, "replay" ) || !strcmp( a->name, "tower" ) || !strcmp( a->name, "accdb" ) ||
                      ( !a->kind_id && ( !strcmp( a->name, "shred" ) || !strcmp( a->name, "net" ) ) );
      int b_cold = name_in( b->name, cold ) && ( strcmp( b->name, "sign" ) || b->kind_id );
      if( protect ) FD_TEST( b_cold );
      if( strcmp( a->name, b->name ) ) FD_TEST( !( name_in( a->name, avx ) && name_in( b->name, avx ) ) );
    }
  }
}

/* Snapshot load gets whole cores where they are free then, steady
   state placement does not move */
FD_UNIT_TEST( test_startup_whole_cores ) {
  /* the last two have offline siblings before the free cores */
  static ulong const OFF[] = { 29, 31, 33, 35, ULONG_MAX };
  for( ulong v=0UL; v<4UL; v++ ) {
    ulong n = v ? 24UL : 32UL;
    static fd_topo_cpus_t cpus[1];
    make_cpus_shape( cpus, 1UL, 1UL, n, 0UL, v<2UL ? SMT_ON : SMT_ADJACENT, v<2UL ? NULL : OFF+2UL*(v-2UL) );
    static fd_topo_t _topo[1];
    fd_topo_t * topo = _topo;
    fd_memset( topo, 0, sizeof(*topo) );
    make_tiles( topo, MAINNET_TILES );
    set_blocklist( topo, (ulong const[]){ 0UL, cpus->cpu[ 0 ].sibling, ULONG_MAX } );
    topo->sleep_obj_id = ULONG_MAX;
    fd_topob_auto_layout_cpus( topo, cpus );

    uchar load[ FD_TILE_MAX ] = {0};
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      fd_topo_tile_t const * tile = &topo->tiles[ i ];
      if( tile->cpu_idx==ULONG_MAX || ( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_POSTSTART ) ) continue;
      load[ tile->cpu_idx ]++;
    }
    ulong whole = 0UL, idle = 0UL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      fd_topo_tile_t const * tile = &topo->tiles[ i ];
      if( fd_topob_tile_priority_type( tile )!=FD_TOPOB_PRIORITY_STARTUP ) continue;
      FD_TEST( load[ tile->cpu_idx ]==1 );
      ulong s = cpus->cpu[ tile->cpu_idx ].sibling;
      whole += (ulong)( s==ULONG_MAX || !load[ s ] );
    }
    for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
      ulong s = cpus->cpu[ i ].sibling;
      idle += (ulong)( cpus->cpu[ i ].online && i!=0UL && s!=0UL && !load[ i ] && ( s==ULONG_MAX || ( s>i && !load[ s ] ) ) );
    }
    FD_TEST( whole==10UL || !idle );
    ulong snapin = topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ].cpu_idx;
    FD_TEST( cpus->cpu[ snapin ].sibling==ULONG_MAX || !load[ cpus->cpu[ snapin ].sibling ] || whole<1UL );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
