#include "fd_topob_layout.h"
#include "../net/fd_net_tile.h"
#include "../../util/tile/fd_tile_private.h" /* fd_tile_private_sibling_idx */

#include <ctype.h>

#define SET_NAME cpu_bv
#define SET_MAX  FD_TILE_MAX
#include "../../util/tmpl/fd_set.c"

#define ALWAYS    FD_TOPOB_TILE_ALWAYS
#define STARTUP   FD_TOPOB_TILE_STARTUP
#define POSTSTART FD_TOPOB_TILE_POSTSTART
#define FLOATING  FD_TOPOB_TILE_FLOATING
#define CRITICAL  FD_TOPOB_TILE_SMT_CRITICAL
#define DEDICATED FD_TOPOB_TILE_DEDICATED
#define THRUPUT   FD_TOPOB_TILE_THROUGHPUT
#define PIN_EFF   FD_TOPOB_TILE_PIN_EFFICIENT

/* Per-tile classes, keyed by tile name.  Auto layout places each
   phase in turn (ALWAYS, then STARTUP, then POSTSTART), walking rows
   top to bottom, so within a phase earlier rows get earlier CPUs in
   the NUMA/sibling ordering.  Reordering rows changes layouts. */

static struct { char const * name; uint flags; } const TILE_CLASS[] = {
  { "backt",  ALWAYS                       },
  { "benchg", ALWAYS|THRUPUT               },
  { "benchs", ALWAYS|THRUPUT               },
  { "net",    ALWAYS                       },
  { "mlx5",   ALWAYS                       },
  { "sock",   ALWAYS|PIN_EFF               },
  { "quic",   ALWAYS                       },
  { "bundle", ALWAYS                       },
  { "verify", ALWAYS|THRUPUT               },
  { "dedup",  ALWAYS                       },
  { "resolv", ALWAYS                       },
  { "pack",   ALWAYS|CRITICAL              },
  { "sign",   ALWAYS                       },
  { "shred",  ALWAYS                       },
  { "event",  ALWAYS                       },
  { "gui",    ALWAYS                       },
  { "rpc",    ALWAYS                       },
  { "gossvf", ALWAYS                       },
  { "gossip", ALWAYS                       },
  { "repair", ALWAYS                       },
  { "rotor",  ALWAYS                       },
  { "rserve", ALWAYS                       },
  { "replay", ALWAYS|THRUPUT               },
  { "tower",  ALWAYS                       },
  { "votor",  ALWAYS                       },
  { "pktgen", ALWAYS                       },
  { "mwaitx", ALWAYS|PIN_EFF               },

  /* Must shut down after snapshot load */
  { "snapct", STARTUP                      },
  { "snapld", STARTUP                      },
  { "snapdc", STARTUP|THRUPUT              },
  { "snapin", STARTUP|THRUPUT              },

  /* Must sleep until snapshot load finishes */
  { "accdb",  POSTSTART|THRUPUT            },
  { "execle", POSTSTART|THRUPUT            },
  { "poh",    POSTSTART|CRITICAL           },
  { "motor",  POSTSTART|CRITICAL           },
  { "execrp", POSTSTART|DEDICATED|THRUPUT  },
  { "txsend", POSTSTART                    },
  { "solcap", POSTSTART|PIN_EFF            },

  /* Yield to the kernel scheduler */
  { "netlnk", FLOATING                     },
  { "metric", FLOATING                     },
  { "diag",   FLOATING                     },
  { "waker",  FLOATING                     },
  { "bencho", FLOATING                     },
  { "l4swap", FLOATING                     },
  { "genesi", FLOATING                     },
  { "ipecho", FLOATING                     },
  { "admin",  FLOATING                     },
  { "snapsv", FLOATING|PIN_EFF             },
  { "snapmk", FLOATING                     },
  { "snapzp", FLOATING                     },
  { "snaprd", FLOATING                     },
};

#undef ALWAYS
#undef STARTUP
#undef POSTSTART
#undef FLOATING
#undef CRITICAL
#undef DEDICATED
#undef THRUPUT
#undef PIN_EFF

#define TILE_CLASS_CNT (sizeof(TILE_CLASS)/sizeof(TILE_CLASS[0]))

uint
fd_topob_tile_class( char const * name ) {
  for( ulong i=0UL; i<TILE_CLASS_CNT; i++ ) {
    if( !strcmp( name, TILE_CLASS[ i ].name ) ) return TILE_CLASS[ i ].flags;
  }
  return 0U;
}

/* The pinned tiles that park and wake each other the most, in
   placement priority.  A wake across an L3 domain costs more than one
   inside it, so these are packed into as few domains as possible,
   mwaitx first.  Floating tiles are not listed: their cpu_idx only
   picks the NUMA node of the pool they run over, not an L3. */

static char const * HOT_TILES[] = {
  "mwaitx",
  "replay",
  "execrp",
  "mlx5",
  NULL
};


static int
tile_name_in( char const *         name,
              char const * const * names ) {
  for( char const * const * p = names; *p; p++ ) {
    if( !strcmp( name, *p ) ) return 1;
  }
  return 0;
}

static int
tile_is_floating( fd_topo_tile_t const * tile ) {
  /* RX only loopback sock copies its associated net tile's CPU affinity,
     so no extra CPU is needed for pinning. */
  return !!( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_FLOATING ) || sock_lo_net_tile_id( tile )!=ULONG_MAX;
}

int
fd_topob_tile_priority_type( fd_topo_tile_t const * tile ) {
  uint cls = fd_topob_tile_class( tile->name );
  if( !cls || tile_is_floating( tile ) ) return FD_TOPOB_PRIORITY_FLOATING;
  if( cls & FD_TOPOB_TILE_STARTUP      ) return FD_TOPOB_PRIORITY_STARTUP;
  if( cls & FD_TOPOB_TILE_SMT_CRITICAL ) return FD_TOPOB_PRIORITY_CRITICAL;
  return FD_TOPOB_PRIORITY_NORMAL;
}

FD_STATIC_ASSERT( FD_TILE_MAX<FD_TOPOB_CPU_SHARED, update_tile_to_cpu_type );

ulong
fd_topob_parse_affinity_cstr( char const * cstr,
                              ushort *     tile_to_cpu,
                              int          allow_repeats,
                              int          allow_shared ) {
  if( !cstr ) return 0UL;
  ulong cnt = 0UL;

  cpu_bv_t cpu_assigned[ cpu_bv_word_cnt ];
  cpu_bv_new( cpu_assigned );

  char const * p = cstr;
  for(;;) {

    while( fd_isspace( (int)p[0] ) ) p++;

    if( p[0]=='f' ) {
      p++;

      ulong float_cnt;

      while( fd_isspace( (int)p[0] ) ) p++;
      if     ( p[0]==','             ) float_cnt = 1UL, p++;
      else if( p[0]=='\0'            ) float_cnt = 1UL;
      else if( !fd_isdigit( (int)p[0] ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (malformed float count)" ));
      else {
        float_cnt = fd_cstr_to_ulong( p );
        if( FD_UNLIKELY( !float_cnt ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (bad float count)" ));
        p++; while( fd_isdigit( (int)p[0] ) ) p++;
        while( fd_isspace( (int)p[0] ) ) p++;
        if( FD_UNLIKELY( !( p[0]==',' || p[0]=='\0' ) ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (bad float count delimiter)" ));
        if( p[0]==',' ) p++;
      }

      do {
        if( FD_UNLIKELY( cnt>=FD_TILE_MAX ) ) FD_LOG_ERR(( "fd_topob: too many affinity entries" ));
        tile_to_cpu[ cnt++ ] = (ushort)65535;
      } while( --float_cnt );

      continue;
    }

    ulong shared = 0UL;
    if( p[0]=='s' ) {
      if( FD_UNLIKELY( !allow_shared ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (shared cpus not supported here)" ));
      p++; shared = FD_TOPOB_CPU_SHARED;
    }

    if( !fd_isdigit( (int)p[0] ) ) {
      if( FD_UNLIKELY( shared || p[0]!='\0' ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (range lo not a cpu)" ));
      break;
    }
    ulong cpu0   = fd_cstr_to_ulong( p );
    ulong cpu1   = cpu0;
    ulong stride = 1UL;
    int   rev    = 0; /* Nh lists N first */
    p++; while( fd_isdigit( (int)p[0] ) ) p++;
    while( fd_isspace( (int)p[0] ) ) p++;
    if( p[0]=='-' ) {
      p++;
      while( fd_isspace( (int)p[0] ) ) p++;
      if( FD_UNLIKELY( !fd_isdigit( (int)p[0] ) ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (range hi not a cpu)" ));
      cpu1 = fd_cstr_to_ulong( p );
      p++; while( fd_isdigit( (int)p[0] ) ) p++;
      while( fd_isspace( (int)p[0] ) ) p++;
      if( p[0]=='/' || p[0]==':' ) {
        p++;
        while( fd_isspace( (int)p[0] ) ) p++;
        if( FD_UNLIKELY( !fd_isdigit( (int)p[0] ) ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (stride not an int)" ));
        stride = fd_cstr_to_ulong( p );
        p++; while( fd_isdigit( (int)p[0] ) ) p++;
      }
    }
    else if( p[0]=='h' ) {
      p++;
      ulong sibling = fd_tile_private_sibling_idx( cpu0 );
      if( sibling!=ULONG_MAX ) {
        rev    = sibling<cpu0;
        cpu1   = fd_ulong_max( cpu0, sibling );
        cpu0   = fd_ulong_min( cpu0, sibling );
        stride = cpu1-cpu0;
      }
    }
    while( fd_isspace( (int)p[0] ) ) p++;
    if( FD_UNLIKELY( !( p[0]==',' || p[0]=='\0' ) ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (bad range delimiter)" ));
    if( p[0]==',' ) p++;
    cpu1++;
    if( FD_UNLIKELY( cpu1<=cpu0 ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (invalid range)"  ));
    if( FD_UNLIKELY( !stride    ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (invalid stride)" ));

    for( ulong cpu=cpu0; cpu<cpu1; cpu+=stride ) {
      if( FD_UNLIKELY( cnt>=FD_TILE_MAX ) ) FD_LOG_ERR(( "fd_topob: too many affinity entries" ));
      if( FD_UNLIKELY( cpu>=FD_TILE_MAX ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (cpu index too large)" )); /* cpu_assigned holds FD_TILE_MAX */
      if( FD_UNLIKELY( !allow_repeats && !shared && cpu_bv_test( cpu_assigned, cpu ) ) ) FD_LOG_ERR(( "fd_topob: malformed affinity string (repeated cpu)" ));
      tile_to_cpu[ cnt++ ] = (ushort)(cpu | shared);
      if( !shared ) cpu_bv_insert( cpu_assigned, cpu );
    }
    if( rev ) { ushort t = tile_to_cpu[ cnt-2UL ]; tile_to_cpu[ cnt-2UL ] = tile_to_cpu[ cnt-1UL ]; tile_to_cpu[ cnt-1UL ] = t; }
  }

  return cnt;
}

#define FD_TOPOB_LIVE_ALWAYS    (1)
#define FD_TOPOB_LIVE_STARTUP   (2)
#define FD_TOPOB_LIVE_POSTSTART (3)

static int
fd_topob_tile_live_phase( fd_topo_tile_t const * tile ) {
  uint cls = fd_topob_tile_class( tile->name );
  if( ( cls & FD_TOPOB_TILE_STARTUP ) || tile->allow_shutdown ) return FD_TOPOB_LIVE_STARTUP;
  if( cls & FD_TOPOB_TILE_POSTSTART ) return FD_TOPOB_LIVE_POSTSTART;
  return FD_TOPOB_LIVE_ALWAYS;
}

int
fd_topob_cpu_overlap_allowed( fd_topo_tile_t const * a,
                              fd_topo_tile_t const * b,
                              int                    floats_share ) {
  if( sock_lo_net_tile_id( a )==b->id || sock_lo_net_tile_id( b )==a->id ) return 1;
  if( floats_share && a->floats && b->floats ) return 1;

  int a_phase = fd_topob_tile_live_phase( a );
  int b_phase = fd_topob_tile_live_phase( b );

  return ( a_phase==FD_TOPOB_LIVE_STARTUP   && b_phase==FD_TOPOB_LIVE_POSTSTART ) ||
         ( a_phase==FD_TOPOB_LIVE_POSTSTART && b_phase==FD_TOPOB_LIVE_STARTUP   );
}

void
fd_topob_validate_cpu_overlaps( fd_topo_t const * topo ) {
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * a = &topo->tiles[ i ];
    if( a->cpu_idx>=FD_TILE_MAX ) continue;

    for( ulong j=i+1UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t const * b = &topo->tiles[ j ];
      if( b->cpu_idx!=a->cpu_idx ) continue;
      if( FD_LIKELY( fd_topob_cpu_overlap_allowed( a, b, 1 ) ) ) continue;

      FD_LOG_ERR(( "tile `%s:%lu` and tile `%s:%lu` are both assigned to CPU %lu and may try to run at the same time",
                   a->name, a->kind_id, b->name, b->kind_id, a->cpu_idx ));
    }
  }
}

static char const *
offline_note( fd_topo_cpus_t const * cpus,
              char                   buf[ static 128 ] ) {
  ulong offline_cnt = 0UL;
  ulong core_cnt    = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    fd_topo_cpu_t const * cpu = &cpus->cpu[ i ];
    offline_cnt += (ulong)!cpu->online;
    core_cnt    += (ulong)( cpu->online && ( cpu->sibling==ULONG_MAX || cpu->sibling>i ) );
  }
  if( FD_LIKELY( !offline_cnt ) ) return "";
  return fd_cstr_printf( buf, 128UL, NULL, " (%lu CPUs are offline, leaving %lu online physical cores; reduce tile counts)", offline_cnt, core_cnt );
}

/* iso tier test: 3 wants an isolated CPU with a non-isolated
   sibling, 2 one whose free threads are all isolated, 1 an isolated
   CPU, -1 a non-isolated one, 0 any */

static int
iso_mismatch( fd_topo_cpus_t const * cpus,
              ulong                  cpu_idx,
              int                    iso ) {
  fd_topo_cpu_t const * cpu = &cpus->cpu[ cpu_idx ];
  if( iso==3 ) return !cpu->isolated || cpu->sibling==ULONG_MAX || cpus->cpu[ cpu->sibling ].isolated;
  if( iso==2 ) return !cpu->isolated || ( cpu->sibling!=ULONG_MAX && !cpus->cpu[ cpu->sibling ].isolated );
  return iso && (iso>0)!=!!cpu->isolated;
}

/* Free CPUs by core type: both threads free (NN, NI, II by isolated
   thread count), sibling absent (N1, I1), sibling taken (NH, IH) */

#define CT_NN 0
#define CT_NI 1
#define CT_II 2
#define CT_N1 3
#define CT_I1 4
#define CT_NH 5
#define CT_IH 6

/* Counts core types as if cpu_id (and its sibling if whole_core) were
   taken, cpu_id ULONG_MAX for none */

static void
core_type_cnt( fd_topo_cpus_t const * cpus,
               cpu_bv_t const         cpu_assigned[ static cpu_bv_word_cnt ],
               ulong                  cpu_id,
               int                    whole_core,
               ulong                  cnt[ static 7 ] ) {
  cpu_bv_t taken[ cpu_bv_word_cnt ];
  cpu_bv_copy( taken, cpu_assigned );
  if( cpu_id!=ULONG_MAX ) {
    cpu_bv_insert( taken, cpu_id );
    if( whole_core && cpus->cpu[ cpu_id ].sibling!=ULONG_MAX ) cpu_bv_insert( taken, cpus->cpu[ cpu_id ].sibling );
  }

  for( ulong t=0UL; t<7UL; t++ ) cnt[ t ] = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    if( cpu_bv_test( taken, i ) ) continue; /* offline CPUs are taken */
    ulong s   = cpus->cpu[ i ].sibling;
    ulong iso = (ulong)!!cpus->cpu[ i ].isolated;
    if(      s==ULONG_MAX            ) cnt[ CT_N1+iso ]++;
    else if( cpu_bv_test( taken, s ) ) cnt[ CT_NH+iso ]++;
    else if( s>i                     ) cnt[ CT_NN+iso+(ulong)!!cpus->cpu[ s ].isolated ]++;
  }
}

/* Exact test that the tiles left still have CPUs.  dem[ phase*3+kind ]
   counts them by phase (always, startup, post-start) and kind
   (critical: whole core, pinned: any CPU, floater: non-isolated CPU).
   Each of the left critical tiles tries each core type, always ones
   first; a post-start one lends its core's threads (qi isolated, qn
   not) to startup tiles, which never run beside it. */

static int
plan_fits( ulong       cnt[ static 7 ],
           ulong const dem[ static 9 ],
           ulong       left,
           ulong       qi,
           ulong       qn ) {
  static uchar const core_ty [ 5 ] = { CT_I1, CT_II, CT_N1, CT_NI, CT_NN };
  static uchar const core_iso[ 5 ] = { 0, 1, 2, 0, 1 }; /* threads of CT_NN..CT_I1 */
  static uchar const core_non[ 5 ] = { 2, 1, 0, 1, 0 };
  if( left ) {
    int post = left<=dem[ 6 ];
    for( ulong t=0UL; t<5UL; t++ ) {
      ulong ty = core_ty[ t ];
      if( !cnt[ ty ] ) continue;
      cnt[ ty ]--;
      int ok = plan_fits( cnt, dem, left-1UL, qi+(post ? core_iso[ ty ] : 0UL), qn+(post ? core_non[ ty ] : 0UL) );
      cnt[ ty ]++;
      if( ok ) return 1;
    }
    return 0;
  }
  ulong i = cnt[ CT_NI ] + 2UL*cnt[ CT_II ] + cnt[ CT_I1 ] + cnt[ CT_IH ];
  ulong n = cnt[ CT_NI ] + 2UL*cnt[ CT_NN ] + cnt[ CT_N1 ] + cnt[ CT_NH ];
  return i+n       >=dem[ 1 ]+dem[ 2 ]+dem[ 7 ]+dem[ 8 ] && n   >=dem[ 2 ]+dem[ 8 ] &&
         i+n+qi+qn >=dem[ 1 ]+dem[ 2 ]+dem[ 4 ]+dem[ 5 ] && n+qn>=dem[ 2 ]+dem[ 5 ]+fd_ulong_sat_sub( dem[ 1 ], i );
}

/* First free CPU from cpu_idx in tier iso (whole_core: with a free
   sibling) that keeps the plan if plan is set.  Tier 2, and a
   dedicated or floater whole core idling an isolated sibling, also
   need the isolated slots left to cover the pinned tiles left. */

static ulong
auto_tile_cpu_scan( fd_topo_cpus_t const * cpus,
                    cpu_bv_t const         cpu_assigned[ static cpu_bv_word_cnt ],
                    ushort const           cpu_ordering[ static FD_TILE_MAX     ],
                    ulong                  cpu_idx,
                    int                    iso,
                    int                    whole_core,
                    int                    is_dedicated,
                   _Bool                   skip_ht_pairs,
                    int                    plan,
                    ulong const            dem[ static 9 ] ) {
  for( ulong j=cpu_idx; j<cpus->cpu_cnt; j++ ) {
    ulong cpu_id  = cpu_ordering[ j ];
    ulong sibling = cpus->cpu[ cpu_id ].sibling;
    if( cpu_bv_test( cpu_assigned, cpu_id ) || iso_mismatch( cpus, cpu_id, iso ) ) continue;
    if( whole_core && sibling!=ULONG_MAX && cpu_bv_test( cpu_assigned, sibling ) ) continue;
    if( !plan ) return cpu_id;

    ulong cnt[ 7 ];
    core_type_cnt( cpus, cpu_assigned, cpu_id, whole_core, cnt );
    if( !plan_fits( cnt, dem, dem[ 0 ]+dem[ 6 ], 0UL, 0UL ) ) continue;
    int guard = iso==2 || ( ( is_dedicated || iso<0 ) && whole_core && sibling!=ULONG_MAX && cpus->cpu[ sibling ].isolated );
    if( !guard ) return cpu_id;
    ulong iso_slots = skip_ht_pairs ? cnt[ CT_NI ]+cnt[ CT_II ]+cnt[ CT_I1 ] : cnt[ CT_NI ]+2UL*cnt[ CT_II ]+cnt[ CT_I1 ]+cnt[ CT_IH ];
    if( iso_slots>=dem[ 0 ]+dem[ 1 ]+fd_ulong_max( dem[ 3 ]+dem[ 4 ], dem[ 6 ]+dem[ 7 ] ) ) return cpu_id;
  }
  return ULONG_MAX;
}

/* In efficient mode pinned tiles take isolated CPUs first and floaters
   never do.  While the tiles left fit, a CPU is only taken if they
   still fit after it, and the optional isolated preference and
   dedicated whole core relax rather than abort.  Pinned non-critical
   tiles first skip all-isolated cores the critical tiles left need. */

static void
auto_tile_cpu( fd_topo_tile_t * tile,
               fd_topo_cpus_t * cpus,
               ulong *          cpu_idx_p,
               cpu_bv_t         cpu_assigned[ static cpu_bv_word_cnt ],
               ushort const     cpu_ordering[ static FD_TILE_MAX     ],
              _Bool             skip_ht_pairs,
               ulong *          spare_siblings,
               int              efficient,
               ulong            dem[ static 9 ],
               ulong            phase ) {
  ulong cpu_idx = *cpu_idx_p;

  ulong cpu_cnt = cpus->cpu_cnt;
  while( cpu_idx<cpu_cnt && cpu_bv_test( cpu_assigned, cpu_ordering[ cpu_idx ] ) ) cpu_idx++;

  /* Certain tiles are latency and throughput critical and
     should not get a HT pair assigned. */
  uint  cls    = fd_topob_tile_class( tile->name );
  int   crit   = !!( cls & FD_TOPOB_TILE_SMT_CRITICAL );
  int   pinned = !!( cls & FD_TOPOB_TILE_EFFICIENT_PINNED );
  ulong cnt[ 7 ];
  core_type_cnt( cpus, cpu_assigned, ULONG_MAX, 0, cnt );
  int plan = efficient && plan_fits( cnt, dem, dem[ 0 ]+dem[ 6 ], 0UL, 0UL );
  dem[ phase*3UL + ( crit ? 0UL : pinned ? 1UL : 2UL ) ]--;
  int iso_hi = efficient ? ( pinned ? 1+( crit && plan ) : -1 ) : 0;
  int iso_lo = efficient && !pinned ? -1 : 0;
  ulong crit_cores = cnt[ CT_II ]+cnt[ CT_I1 ];
  if( plan && pinned && !crit && crit_cores && crit_cores<=dem[ 0 ]+dem[ 3 ]+dem[ 6 ] &&
      cnt[ CT_NI ]+cnt[ CT_IH ]>=dem[ 1 ]+fd_ulong_max( dem[ 4 ], dem[ 7 ] )+1UL ) iso_hi = 3;

  ulong cpu_id     = ULONG_MAX;
  int   whole_core = 0;
  int   tier_free  = 0;
  for( int iso=iso_hi; iso>=iso_lo && cpu_id==ULONG_MAX; iso-=1+( iso==3 ) ) {
    ulong first = cpu_idx;
    while( first<cpu_cnt && ( cpu_bv_test( cpu_assigned, cpu_ordering[ first ] ) || iso_mismatch( cpus, cpu_ordering[ first ], iso ) ) ) first++;
    tier_free = first<cpu_cnt;
    if( !tier_free ) continue;

    int is_dedicated = !crit && *spare_siblings && ( cls & FD_TOPOB_TILE_DEDICATED ) && cpus->cpu[ cpu_ordering[ first ] ].sibling!=ULONG_MAX;
    whole_core = crit || is_dedicated || skip_ht_pairs;
    if( whole_core ) {
      cpu_id = auto_tile_cpu_scan( cpus, cpu_assigned, cpu_ordering, cpu_idx, iso, 1, is_dedicated, skip_ht_pairs, plan, dem );
      if( cpu_id!=ULONG_MAX ) { *spare_siblings -= (ulong)is_dedicated; break; }
      if( !is_dedicated ) continue;
      *spare_siblings = 0UL; /* spare logical CPUs can be half cores */
      whole_core      = 0;
    }
    cpu_id = auto_tile_cpu_scan( cpus, cpu_assigned, cpu_ordering, cpu_idx, iso, 0, 0, skip_ht_pairs, plan, dem );
  }
  if( FD_UNLIKELY( cpu_id==ULONG_MAX ) ) {
    char note[ 128 ];
    if( tier_free ) FD_LOG_ERR(( "auto layout cannot set affinity for tile `%s:%lu` because all the CPUs are already assigned or have a HT pair assigned%s", tile->name, tile->kind_id, offline_note( cpus, note ) ));
    FD_LOG_ERR(( "auto layout cannot set affinity for tile `%s:%lu` because all the CPUs are already assigned%s%s", tile->name, tile->kind_id,
                 iso_lo ? " or isolated by isolcpus=" : "", offline_note( cpus, note ) ));
  }

  cpu_bv_insert( cpu_assigned, cpu_id );
  if( whole_core && cpus->cpu[ cpu_id ].sibling!=ULONG_MAX ) cpu_bv_insert( cpu_assigned, cpus->cpu[ cpu_id ].sibling );
  tile->cpu_idx = cpu_id;

  *cpu_idx_p = cpu_idx;
}

static ulong
l3_free_core_cnt( fd_topo_cpus_t const * cpus,
                  cpu_bv_t const         cpu_assigned[ static cpu_bv_word_cnt ],
                  ulong                  l3_idx,
                  int                    iso ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    fd_topo_cpu_t const * cpu = &cpus->cpu[ i ];
    if( cpu->l3_idx!=l3_idx || cpu_bv_test( cpu_assigned, i ) || iso_mismatch( cpus, i, iso ) ) continue;
    if( cpu->sibling!=ULONG_MAX && ( cpu_bv_test( cpu_assigned, cpu->sibling ) ||
        ( cpu->sibling<i && !iso_mismatch( cpus, cpu->sibling, iso ) ) ) ) continue; /* core counted once */
    cnt++;
  }
  return cnt;
}

/* Place a hot tile on the first free physical core of L3 domain
   *hot_l3, sibling left empty.  When it is full, the domain with the
   most free cores becomes the hot one.  The l3_layout gate leaves a
   whole core for every tile, so this never needs the plan. */

static void
auto_tile_cpu_l3( fd_topo_tile_t * tile,
                  fd_topo_cpus_t * cpus,
                  ulong *          hot_l3,
                  cpu_bv_t         cpu_assigned[ static cpu_bv_word_cnt ],
                  ushort const     cpu_ordering[ static FD_TILE_MAX     ],
                  ulong            dem[ static 9 ] ) {
  uint cls    = fd_topob_tile_class( tile->name );
  int  pinned = !!( cls & FD_TOPOB_TILE_EFFICIENT_PINNED );
  dem[ ( ( cls & FD_TOPOB_TILE_POSTSTART ) ? 6UL : 0UL ) + ( pinned ? 1UL : 2UL ) ]--; /* hot tiles are not critical */
  int iso = pinned ? 1 : -1;
retry:
  if( *hot_l3==ULONG_MAX || !l3_free_core_cnt( cpus, cpu_assigned, *hot_l3, iso ) ) {
    ulong best_cnt = 0UL;
    for( ulong l3=0UL; l3<cpus->l3_cnt; l3++ ) {
      ulong cnt = l3_free_core_cnt( cpus, cpu_assigned, l3, iso );
      if( cnt>best_cnt ) { best_cnt = cnt; *hot_l3 = l3; }
    }
    if( !best_cnt && iso>0 ) { iso = 0; goto retry; }
    char note[ 128 ];
    if( FD_UNLIKELY( !best_cnt ) ) FD_LOG_ERR(( "auto layout cannot set affinity for tile `%s:%lu` because all the CPUs are already assigned or have a HT pair assigned%s", tile->name, tile->kind_id, offline_note( cpus, note ) ));
  }

  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    ulong cpu_idx = cpu_ordering[ i ];
    fd_topo_cpu_t const * cpu = &cpus->cpu[ cpu_idx ];
    if( cpu->l3_idx!=*hot_l3 || cpu_bv_test( cpu_assigned, cpu_idx ) || iso_mismatch( cpus, cpu_idx, iso ) ) continue;
    if( cpu->sibling!=ULONG_MAX && cpu_bv_test( cpu_assigned, cpu->sibling ) ) continue;
    cpu_bv_insert( cpu_assigned, cpu_idx );
    if( cpu->sibling!=ULONG_MAX ) cpu_bv_insert( cpu_assigned, cpu->sibling );
    tile->cpu_idx = cpu_idx;
    return;
  }
  FD_LOG_ERR(( "auto layout found no free core in L3 %lu for tile `%s:%lu`", *hot_l3, tile->name, tile->kind_id ));
}

#undef CT_NN
#undef CT_NI
#undef CT_II
#undef CT_N1
#undef CT_I1
#undef CT_NH
#undef CT_IH

static ulong
name_idx( char const *         name,
          char const * const * names ) {
  for( ulong i=0UL; names[ i ]; i++ ) if( !strcmp( name, names[ i ] ) ) return i;
  return ULONG_MAX;
}

/* Whole core rank of a steady tile, lower first, tier in bits 24+ */

#define SMT_TIER_COLD (7UL)

static ulong
smt_rank( fd_topo_tile_t const * tile,
          ulong                  execrp_floor,
          int                    replay_first ) {
  static char const * const T4[] = { "tower", "votor", "shred", "net", "mlx5", "sock", "accdb", NULL };
  static char const * const T5[] = { "repair", "rotor", NULL };
  static char const * const T6[] = { "execle", "dedup", "sign", "resolv", "quic", "verify", "txsend", "bundle", "shred", "net", "mlx5", "sock", NULL };
  static char const * const T7[] = { "gui", "rpc", "event", "rserve", "gossip", "gossvf", NULL };

  char const * name = tile->name;
  ulong        k    = tile->kind_id;
  if( fd_topob_tile_class( name ) & FD_TOPOB_TILE_SMT_CRITICAL ) return k;
  if( !strcmp( name, "replay" ) ) return replay_first ? 1UL<<24 : 2UL<<24;
  if( !strcmp( name, "execrp" ) ) return ( k>=execrp_floor ? 3UL<<24 : replay_first ? 2UL<<24 : 1UL<<24 ) | k;
  if( !strcmp( name, "sign" ) && k ) return (SMT_TIER_COLD<<24) | (4095UL<<12) | k;
  ulong i;
  if( !k && (i=name_idx( name, T4 ))!=ULONG_MAX ) return (4UL<<24)            | (i<<12);
  if(       (i=name_idx( name, T5 ))!=ULONG_MAX ) return (5UL<<24)            | (i<<12) | k;
  if(       (i=name_idx( name, T6 ))!=ULONG_MAX ) return (6UL<<24)            | (i<<12) | k;
  if(       (i=name_idx( name, T7 ))!=ULONG_MAX ) return (SMT_TIER_COLD<<24) | (i<<12) | k;
  return (6UL<<24) | (4094UL<<12) | k;
}

#define SMT_WHOLE (0)
#define SMT_HALF  (1)
#define SMT_PAIR  (2)

/* Shares only as many cores as needed, lowest ranked tiles first.
   Returns 0 if the tiles do not fit or a critical tile would pair. */

static int
smt_plan( fd_topo_t const *      topo,
          fd_topo_cpus_t const * cpus,
          cpu_bv_t const         assigned[ static cpu_bv_word_cnt ],
          ulong const *          tile_idx,
          ulong                  cnt,
          ulong                  execrp_floor,
          int                    efficient,
          uchar *                mode,
          ulong *                partner ) {
  static char const * const AVX[] = { "verify", "sign", "shred", "benchg", NULL };

  ulong p2 = 0UL, p1 = 0UL, half = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    if( cpu_bv_test( assigned, i ) ) continue;
    ulong s = cpus->cpu[ i ].sibling;
    if(      s==ULONG_MAX                ) p1++;
    else if( !cpu_bv_test( assigned, s ) ) p2 += (ulong)( s>i );
    else                                   half++;
  }
  ulong h = fd_ulong_min( half, fd_ulong_sat_sub( cnt, p2+p1 ) );
  ulong d = fd_ulong_sat_sub( cnt, p2+p1+half );
  if( FD_UNLIKELY( d>p2 ) ) return 0;
  ulong whole = cnt - h - 2UL*d;

  ulong top = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ tile_idx[ i ] ];
    top += (ulong)( ( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_SMT_CRITICAL ) || !strcmp( tile->name, "replay" ) ||
                    ( !strcmp( tile->name, "execrp" ) && tile->kind_id<execrp_floor ) );
  }
  int replay_first = whole>=top;

  ulong order[ FD_TOPO_MAX_TILES ];
  ulong key  [ FD_TOPO_MAX_TILES ];
  FD_TEST( cnt<=FD_TOPO_MAX_TILES );
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong k = smt_rank( &topo->tiles[ tile_idx[ i ] ], execrp_floor, replay_first );
    ulong j = i;
    for( ; j && key[ j-1UL ]>k; j-- ) { key[ j ] = key[ j-1UL ]; order[ j ] = order[ j-1UL ]; }
    key[ j ] = k; order[ j ] = i;
  }
  for( ulong j=whole; j<cnt; j++ ) {
    if( FD_UNLIKELY( !(key[ j ]>>24) ) ) return 0;
  }

  for( ulong j=0UL; j<cnt; j++ ) {
    mode   [ order[ j ] ] = (uchar)( j<whole ? SMT_WHOLE : j<whole+h ? SMT_HALF : SMT_PAIR );
    partner[ order[ j ] ] = ULONG_MAX;
  }

  for( ulong pass=0UL; pass<6UL; pass++ ) {
    for( ulong a=whole+h; a<cnt; a++ ) {
      if( partner[ order[ a ] ]!=ULONG_MAX ) continue;
      fd_topo_tile_t const * ta = &topo->tiles[ tile_idx[ order[ a ] ] ];
      for( ulong b=cnt-1UL; b>a; b-- ) {
        if( partner[ order[ b ] ]!=ULONG_MAX ) continue;
        fd_topo_tile_t const * tb = &topo->tiles[ tile_idx[ order[ b ] ] ];
        int hot_a  = (key[ a ]>>24)<=4UL && !( fd_topob_tile_class( ta->name ) & FD_TOPOB_TILE_DEDICATED );
        int cold_a = (key[ a ]>>24)==SMT_TIER_COLD;
        int cold_b = (key[ b ]>>24)==SMT_TIER_COLD;
        int same   = !strcmp( ta->name, tb->name );
        int avx    = !same && name_idx( ta->name, AVX )!=ULONG_MAX && name_idx( tb->name, AVX )!=ULONG_MAX;
        int pin_a  = !!( fd_topob_tile_class( ta->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED );
        int pin_b  = !!( fd_topob_tile_class( tb->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED );
        int strict = !avx && ( !efficient || pin_a==pin_b );
        int ok;
        switch( pass ) { /* a hot tile that must share gets a cold sibling */
          case 0UL: ok = strict && hot_a && cold_b;               break;
          case 1UL: ok = strict && cold_a && cold_b;              break;
          case 2UL: ok = strict && same;                          break;
          case 3UL: ok = strict && cold_b;                        break;
          case 4UL: ok = strict;                                  break;
          default:  ok = 1;                                       break;
        }
        if( !ok ) continue;
        if( FD_UNLIKELY( pass==5UL && avx ) ) FD_LOG_WARNING(( "auto layout is short of physical cores and puts AVX heavy tile `%s:%lu` on the hyperthread sibling of tile `%s:%lu`",
                                                        tb->name, tb->kind_id, ta->name, ta->kind_id ));
        partner[ order[ a ] ] = order[ b ];
        partner[ order[ b ] ] = order[ a ];
        break;
      }
    }
  }
  return 1;
}

/* Places plan entries [lo,hi) in CPU order */

static void
smt_place( fd_topo_t *            topo,
           fd_topo_cpus_t const * cpus,
           cpu_bv_t               assigned[ static cpu_bv_word_cnt ],
           ushort const           cpu_ordering[ static FD_TILE_MAX ],
           ulong const *          tile_idx,
           ulong                  lo,
           ulong                  hi,
           ulong                  cnt,
           uchar *                mode,
           ulong *                partner,
           int                    efficient ) {
  ulong p2_free = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    ulong s = cpus->cpu[ i ].sibling;
    p2_free += (ulong)( s!=ULONG_MAX && s>i && !cpu_bv_test( assigned, i ) && !cpu_bv_test( assigned, s ) );
  }
  ulong pairs_left = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) pairs_left += (ulong)( mode[ i ]==SMT_PAIR && partner[ i ]>i && partner[ i ]!=ULONG_MAX &&
                                                        topo->tiles[ tile_idx[ i ] ].cpu_idx==ULONG_MAX );

  for( ulong i=lo; i<hi; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ tile_idx[ i ] ];
    if( tile->cpu_idx!=ULONG_MAX ) continue;
    int avoid = efficient && !( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED );
    int pair  = mode[ i ]==SMT_PAIR && partner[ i ]!=ULONG_MAX;
    fd_topo_tile_t * mate = pair ? &topo->tiles[ tile_idx[ partner[ i ] ] ] : NULL;
    int mate_avoid = pair && efficient && !( fd_topob_tile_class( mate->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED );

    ulong pick = ULONG_MAX;
    ulong any  = ULONG_MAX;
    for( ulong j=0UL; j<cpus->cpu_cnt && pick==ULONG_MAX; j++ ) {
      ulong c = cpu_ordering[ j ];
      fd_topo_cpu_t const * cpu = &cpus->cpu[ c ];
      if( cpu_bv_test( assigned, c ) || ( avoid && cpu->isolated ) ) continue;
      if( any==ULONG_MAX ) any = c;
      ulong s        = cpu->sibling;
      int   sib_free = s!=ULONG_MAX && !cpu_bv_test( assigned, s );
      int   ok;
      if(      pair                ) ok = sib_free && !( mate_avoid && cpus->cpu[ s ].isolated );
      else if( mode[ i ]==SMT_HALF ) ok = s!=ULONG_MAX && !sib_free;
      else                           ok = s==ULONG_MAX || ( sib_free && p2_free>pairs_left );
      if( ok ) pick = c;
    }

    if( FD_UNLIKELY( pick==ULONG_MAX ) ) {
      if( FD_UNLIKELY( any==ULONG_MAX ) ) {
        char note[ 128 ];
        FD_LOG_ERR(( "auto layout cannot set affinity for tile `%s:%lu` because all the CPUs are already assigned%s%s", tile->name, tile->kind_id,
                     avoid ? " or isolated by isolcpus=" : "", offline_note( cpus, note ) ));
      }
      if( pair ) { /* the mate is placed on its own */
        mode   [ partner[ i ] ] = SMT_HALF;
        partner[ partner[ i ] ] = ULONG_MAX;
        pairs_left--;
      }
      pick = any;
      tile->cpu_idx = pick;
      cpu_bv_insert( assigned, pick );
      ulong s = cpus->cpu[ pick ].sibling;
      if( s!=ULONG_MAX && !cpu_bv_test( assigned, s ) ) p2_free--;
      continue;
    }

    ulong s = cpus->cpu[ pick ].sibling;
    tile->cpu_idx = pick;
    cpu_bv_insert( assigned, pick );
    if( mode[ i ]==SMT_HALF || s==ULONG_MAX ) continue;
    cpu_bv_insert( assigned, s );
    p2_free--;
    if( pair ) { mate->cpu_idx = s; pairs_left--; }
  }
}

/* Whole cores free during snapshot load for startup tiles, snapin
   first, preferring execrp's cores */

static void
auto_startup_cpus( fd_topo_t *            topo,
                   fd_topo_cpus_t const * cpus,
                   cpu_bv_t               snap[ static cpu_bv_word_cnt ],
                   ushort const           cpu_ordering[ static FD_TILE_MAX ],
                   int                    efficient ) {
  static char const * const ORDER[] = { "snapin", "snapdc", "snapld", "snapct", NULL };

  ulong idx[ FD_TOPO_MAX_TILES ];
  ulong cnt = 0UL;
  for( ulong r=0UL; r<4UL+TILE_CLASS_CNT; r++ ) {
    char const * name = r<4UL ? ORDER[ r ] : TILE_CLASS[ r-4UL ].name;
    if( r>=4UL && ( !( TILE_CLASS[ r-4UL ].flags & FD_TOPOB_TILE_STARTUP ) || name_idx( name, ORDER )!=ULONG_MAX ) ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      if( tile_is_floating( &topo->tiles[ j ] ) || strcmp( topo->tiles[ j ].name, name ) ) continue;
      idx[ cnt++ ] = j;
    }
  }
  if( !cnt ) return;

  cpu_bv_t banned[ cpu_bv_word_cnt ]; cpu_bv_new( banned );
  cpu_bv_t execrp[ cpu_bv_word_cnt ]; cpu_bv_new( execrp );
  for( ulong i=0UL; i<topo->blocklist_cores_cnt; i++ ) cpu_bv_insert( banned, topo->blocklist_cores_cpu_idx[ i ] );
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) if( !cpus->cpu[ i ].online ) cpu_bv_insert( banned, i );
  for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ j ];
    ulong c = tile->cpu_idx;
    if( c>=cpus->cpu_cnt ) continue;
    uint  cls = fd_topob_tile_class( tile->name );
    ulong s   = cpus->cpu[ c ].sibling;
    if( !strcmp( tile->name, "execrp" ) ) { cpu_bv_insert( execrp, c ); if( s!=ULONG_MAX ) cpu_bv_insert( execrp, s ); }
    if( !( cls & FD_TOPOB_TILE_ALWAYS ) ) continue;
    cpu_bv_insert( banned, c );
    if( ( cls & FD_TOPOB_TILE_SMT_CRITICAL ) && s!=ULONG_MAX ) cpu_bv_insert( banned, s );
  }

  ulong free_cnt = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) free_cnt += (ulong)!cpu_bv_test( snap, i );
  ulong spare = fd_ulong_sat_sub( free_cnt, cnt ); /* siblings that can idle */

  for( ulong k=0UL; k<cnt; k++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ idx[ k ] ];
    int avoid = efficient && !( fd_topob_tile_class( tile->name ) & FD_TOPOB_TILE_EFFICIENT_PINNED );
    ulong pick = ULONG_MAX;
    for( ulong pass=0UL; pass<4UL && pick==ULONG_MAX; pass++ ) {
      for( ulong j=0UL; j<cpus->cpu_cnt && pick==ULONG_MAX; j++ ) {
        ulong c = cpu_ordering[ j ];
        ulong s = cpus->cpu[ c ].sibling;
        if( avoid && cpus->cpu[ c ].isolated ) continue;
        switch( pass ) {
          case 0UL:
          case 1UL: if( cpu_bv_test( snap, c ) || ( s!=ULONG_MAX && ( cpu_bv_test( snap, s ) || !spare ) ) || ( !pass && !cpu_bv_test( execrp, c ) ) ) continue; break;
          case 2UL: if( cpu_bv_test( snap, c ) ) continue; break;
          default:  if( cpu_bv_test( banned, c ) ) continue; break;
        }
        pick = c;
        if( pass<2UL && s!=ULONG_MAX ) { cpu_bv_insert( snap, s ); spare--; }
      }
    }
    if( FD_UNLIKELY( pick==ULONG_MAX ) ) {
      char note[ 128 ];
      FD_LOG_ERR(( "auto layout cannot set affinity for tile `%s:%lu` because all the CPUs are already assigned%s%s", tile->name, tile->kind_id,
                   avoid ? " or isolated by isolcpus=" : "", offline_note( cpus, note ) ));
    }
    tile->cpu_idx = pick;
    cpu_bv_insert( snap,   pick );
    cpu_bv_insert( banned, pick );
  }
}

void
fd_topob_auto_layout_cpus( fd_topo_t *      topo,
                           fd_topo_cpus_t * cpus ) {
  /* See the strategy in fd_topob_layout.h */

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    tile->cpu_idx = ULONG_MAX;
  }

  ushort   cpu_ordering[ FD_TILE_MAX ] = {0};
  cpu_bv_t pairs_assigned[ cpu_bv_word_cnt ]; cpu_bv_new( pairs_assigned );
  FD_STATIC_ASSERT( FD_TILE_MAX<=USHORT_MAX, layout );

  ulong next_cpu_idx = 0UL;
  for( ulong i=0UL; i<cpus->numa_node_cnt; i++ ) {
    for( ulong j=0UL; j<cpus->cpu_cnt; j++ ) {
      fd_topo_cpu_t * cpu = &cpus->cpu[ j ];

      if( FD_UNLIKELY( cpu_bv_test( pairs_assigned, j ) || cpu->numa_node!=i ) ) continue;

      FD_TEST( next_cpu_idx<FD_TILE_MAX );
      cpu_ordering[ next_cpu_idx++ ] = (ushort)j;

      if( FD_UNLIKELY( cpu->sibling!=ULONG_MAX ) ) {
        /* If the CPU has a HT pair, place it immediately after so they
           are sequentially assigned. */
        FD_TEST( next_cpu_idx<FD_TILE_MAX );
        cpu_ordering[ next_cpu_idx++ ] = (ushort)cpu->sibling;
        cpu_bv_insert( pairs_assigned, cpu->sibling );
      }
    }
  }

  FD_TEST( next_cpu_idx==cpus->cpu_cnt );

  /* excluded cpus are simply considered already assigned */
  cpu_bv_t cpu_assigned[ cpu_bv_word_cnt ];
  cpu_bv_new( cpu_assigned );
  for( ulong i=0UL; i<topo->blocklist_cores_cnt; i++ ) {
    FD_TEST( topo->blocklist_cores_cpu_idx[ i ]<FD_TILE_MAX );
    cpu_bv_insert( cpu_assigned, topo->blocklist_cores_cpu_idx[ i ] );
  }
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) if( !cpus->cpu[ i ].online ) cpu_bv_insert( cpu_assigned, i );

  /* Compute total number of available physical cores */
  ulong available_physical = 0UL;
  ulong available_floater  = 0UL; /* no isolated thread */
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    ulong sibling = cpus->cpu[ i ].sibling;
    if( !cpu_bv_test( cpu_assigned, i   ) &&
        !cpu_bv_test( pairs_assigned, i ) &&
        ( sibling==ULONG_MAX ||
          !cpu_bv_test( cpu_assigned, sibling ) ) ) {
      available_physical++;
      available_floater += (ulong)( !cpus->cpu[ i ].isolated && ( sibling==ULONG_MAX || !cpus->cpu[ sibling ].isolated ) );
    }
  }

  /* Tiles that need assignment, dem[ phase*3+kind ] by phase (always,
     startup, post-start) and kind (SMT critical, other pinned,
     efficient mode floater, which skips isolated CPUs) */
  ulong dem[ 9 ] = {0};
  for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ j ];
    uint cls = fd_topob_tile_class( tile->name );
    if( !cls || tile_is_floating( tile ) ) continue;
    ulong phase = ( cls & FD_TOPOB_TILE_STARTUP ) ? 1UL : ( cls & FD_TOPOB_TILE_POSTSTART ) ? 2UL : 0UL;
    ulong kind  = ( cls & FD_TOPOB_TILE_SMT_CRITICAL ) ? 0UL : ( cls & FD_TOPOB_TILE_EFFICIENT_PINNED ) ? 1UL : 2UL;
    dem[ phase*3UL+kind ]++;
  }
  FD_TEST( !dem[ 3 ] ); /* plan_fits has no SMT critical startup tile */
  ulong always_tiles_to_assign  = dem[ 0 ]+dem[ 1 ]+dem[ 2 ];
  ulong startup_tiles_to_assign = dem[ 3 ]+dem[ 4 ]+dem[ 5 ];
  ulong post_start_tiles_to_assign = dem[ 6 ]+dem[ 7 ]+dem[ 8 ];
  ulong tiles_to_assign = always_tiles_to_assign +
      fd_ulong_max( startup_tiles_to_assign, post_start_tiles_to_assign );
  ulong floaters_to_assign = dem[ 2 ] + fd_ulong_max( dem[ 5 ], dem[ 8 ] );

  /* L3 packing gives the hot post-start tiles their own cores instead
     of sharing with startup tiles, so it needs that many more.
     Performance mode, single-L3 hosts, hosts with a partial cache
     topology and hosts too small for it keep the sequential layout. */
  ulong hot_post_start_tiles    = 0UL;
  ulong hot_post_start_floaters = 0UL;
  for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ j ];
    if( tile_is_floating( tile ) ) continue;
    uint cls = fd_topob_tile_class( tile->name );
    int  hot = ( cls & FD_TOPOB_TILE_POSTSTART ) && tile_name_in( tile->name, HOT_TILES );
    hot_post_start_tiles    += (ulong)hot;
    hot_post_start_floaters += (ulong)( hot && !( cls & FD_TOPOB_TILE_EFFICIENT_PINNED ) );
  }
  ulong l3_tiles_to_assign = always_tiles_to_assign + hot_post_start_tiles +
      fd_ulong_max( startup_tiles_to_assign, post_start_tiles_to_assign-hot_post_start_tiles );
  ulong l3_floaters_to_assign = dem[ 2 ] + hot_post_start_floaters +
      fd_ulong_max( dem[ 5 ], dem[ 8 ]-hot_post_start_floaters );
  int efficient = topo->sleep_obj_id!=ULONG_MAX;
  int l3_layout = efficient && fd_topo_cpus_l3_complete( cpus ) &&
                  available_physical>=l3_tiles_to_assign && available_floater>=l3_floaters_to_assign;

  /* If we have enough physical cores (excluding HT siblings) for all
     tiles that need assignment, exclude HT siblings so that no tile
     gets scheduled on a hyperthread pair. */
  _Bool skip_ht_pairs = available_physical>=tiles_to_assign && ( !efficient || available_floater>=floaters_to_assign );

  /* Otherwise spend the spare logical CPUs on whole cores for the
     dedicated tiles.  Each costs its sibling, like a critical tile.
     The L3 layout already places them on whole cores. */
  ulong spare_siblings = 0UL;
  if( !skip_ht_pairs && !l3_layout ) {
    ulong free_logical = 0UL;
    for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) free_logical += !cpu_bv_test( cpu_assigned, i );
    ulong critical_cnt = 0UL;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) critical_cnt += (ulong)!!( fd_topob_tile_class( topo->tiles[ j ].name ) & FD_TOPOB_TILE_SMT_CRITICAL );
    spare_siblings = fd_ulong_sat_sub( free_logical, tiles_to_assign+critical_cnt );
  }

  /* Short of physical cores: share only as many as needed, by rank */
  ulong  steady_idx    [ FD_TOPO_MAX_TILES ];
  uchar  steady_mode   [ FD_TOPO_MAX_TILES ];
  ulong  steady_partner[ FD_TOPO_MAX_TILES ];
  ulong  steady_cnt = 0UL;
  ulong  always_cnt = 0UL;
  int    graded     = !skip_ht_pairs && !l3_layout;
  /* Efficient mode floaters avoid isolcpus=, which the plan ignores */
  for( ulong i=0UL; i<cpus->cpu_cnt && graded && efficient; i++ ) graded = cpu_bv_test( cpu_assigned, i ) || !cpus->cpu[ i ].isolated;
  cpu_bv_t numa_fence[ cpu_bv_word_cnt ]; cpu_bv_new( numa_fence );

  /* Pack, poh, accdb and execle go first into one L3 with the cores the
     plan gives them, pairing execle to fit and spilling the highest to
     the next L3.  The rest is planned around them, or without them if
     it then does not fit. */
  static char const * const GROUP[] = { "pack", "poh", "motor", "accdb", "execle", NULL };
  int group = !efficient && fd_topo_cpus_l3_complete( cpus );
  cpu_bv_t base      [ cpu_bv_word_cnt ]; cpu_bv_copy( base, cpu_assigned );
  cpu_bv_t group_post[ cpu_bv_word_cnt ]; cpu_bv_new( group_post ); /* free during snapshot load */
  for( ulong attempt=0UL;; attempt++ ) {
    if( graded ) {
      steady_cnt = 0UL;
      for( ulong r=0UL; r<TILE_CLASS_CNT; r++ ) {
        if( !( TILE_CLASS[ r ].flags & FD_TOPOB_TILE_ALWAYS ) ) continue;
        for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
          if( tile_is_floating( &topo->tiles[ j ] ) || topo->tiles[ j ].cpu_idx!=ULONG_MAX || strcmp( topo->tiles[ j ].name, TILE_CLASS[ r ].name ) ) continue;
          steady_idx[ steady_cnt++ ] = j;
        }
      }
      always_cnt = steady_cnt;
      for( ulong r=0UL; r<TILE_CLASS_CNT; r++ ) {
        if( !( TILE_CLASS[ r ].flags & FD_TOPOB_TILE_POSTSTART ) ) continue;
        for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
          if( topo->tiles[ j ].cpu_idx!=ULONG_MAX || strcmp( topo->tiles[ j ].name, TILE_CLASS[ r ].name ) ) continue;
          steady_idx[ steady_cnt++ ] = j;
        }
      }
      /* Fill the first NUMA nodes that fit before crossing to the next */
      ulong need = steady_cnt;
      for( ulong i=0UL; i<steady_cnt; i++ ) need += (ulong)!!( fd_topob_tile_class( topo->tiles[ steady_idx[ i ] ].name ) & FD_TOPOB_TILE_SMT_CRITICAL );
      ulong node_cnt = 0UL;
      ulong free_cnt = 0UL;
      for( ; node_cnt<cpus->numa_node_cnt && free_cnt<need; node_cnt++ ) {
        for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) free_cnt += (ulong)( cpus->cpu[ i ].numa_node==node_cnt && !cpu_bv_test( cpu_assigned, i ) );
      }
      for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
        if( cpus->cpu[ i ].numa_node>=node_cnt && !cpu_bv_test( cpu_assigned, i ) ) cpu_bv_insert( numa_fence, i );
      }
      cpu_bv_union( cpu_assigned, cpu_assigned, numa_fence );
      graded = smt_plan( topo, cpus, cpu_assigned, steady_idx, steady_cnt, spare_siblings, efficient, steady_mode, steady_partner );
      if( !graded ) {
        cpu_bv_subtract( cpu_assigned, cpu_assigned, numa_fence );
        cpu_bv_new( numa_fence );
        graded = smt_plan( topo, cpus, cpu_assigned, steady_idx, steady_cnt, spare_siblings, efficient, steady_mode, steady_partner );
      }
    }
    if( attempt==1UL && !graded ) {
      for( ulong j=0UL; j<topo->tile_cnt; j++ ) topo->tiles[ j ].cpu_idx = ULONG_MAX;
      cpu_bv_copy( cpu_assigned, base );
      cpu_bv_new( numa_fence );
      cpu_bv_new( group_post );
      graded = 1;
      continue;
    }
    if( attempt || !group || !( graded || skip_ht_pairs ) ) break;

    ulong lead = 0UL, ex = 0UL, ew = 0UL; /* cores of pack, poh and accdb, execle, execle on whole cores */
    for( ulong i=0UL; i<( graded ? steady_cnt : topo->tile_cnt ); i++ ) {
      ulong g = name_idx( topo->tiles[ graded ? steady_idx[ i ] : i ].name, GROUP );
      lead += (ulong)( g<4UL );
      ex   += (ulong)( g==4UL );
      ew   += (ulong)( g==4UL && ( !graded || steady_mode[ i ]==SMT_WHOLE ) );
    }
    /* First L3 in CPU order that fits, else fits execle paired, else the largest */
    ulong l3 = ULONG_MAX, l3_cores = 0UL, best = 0UL;
    for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
      ulong k = cpus->cpu[ cpu_ordering[ i ] ].l3_idx;
      if( k==ULONG_MAX || ( i && k==cpus->cpu[ cpu_ordering[ i-1UL ] ].l3_idx ) ) continue;
      ulong c     = l3_free_core_cnt( cpus, cpu_assigned, k, 0 );
      ulong score = c>=lead+ew+(ex-ew+1UL)/2UL ? ULONG_MAX : c>=lead+(ex+1UL)/2UL ? ULONG_MAX-1UL : c;
      if( score>best ) { best = score; l3 = k; l3_cores = c; }
    }
    while( ew && lead+ew+(ex-ew+1UL)/2UL>l3_cores ) ew--; /* the lowest execle stay whole */
    ulong e = 0UL;
    for( ulong g=0UL; GROUP[ g ] && l3!=ULONG_MAX; g++ ) {
      for( ulong j=0UL; j<topo->tile_cnt && l3!=ULONG_MAX; j++ ) {
        fd_topo_tile_t * tile = &topo->tiles[ j ];
        if( tile->cpu_idx!=ULONG_MAX || strcmp( tile->name, GROUP[ g ] ) ) continue;
        ulong c = ULONG_MAX;
        for( ulong d=0UL; d<cpus->l3_cnt && c==ULONG_MAX; d++ ) {
          for( ulong i=0UL; i<cpus->cpu_cnt && c==ULONG_MAX; i++ ) {
            ulong k = cpu_ordering[ i ];
            ulong s = cpus->cpu[ k ].sibling;
            if( cpus->cpu[ k ].l3_idx==l3 && !cpu_bv_test( cpu_assigned, k ) && ( s==ULONG_MAX || !cpu_bv_test( cpu_assigned, s ) ) ) c = k;
          }
          if( c==ULONG_MAX ) l3 = (l3+1UL)%cpus->l3_cnt;
        }
        if( c==ULONG_MAX ) { l3 = ULONG_MAX; break; } /* the rest is placed as usual */
        ulong s = cpus->cpu[ c ].sibling;
        ulong m = ULONG_MAX; /* tile on the sibling, which goes to the rest if s is cleared */
        if( g<4UL ) {
          for( ulong i=0UL; i<steady_cnt && graded; i++ ) { /* as planned */
            if( steady_idx[ i ]!=j ) continue;
            if( steady_mode[ i ]==SMT_PAIR && steady_partner[ i ]!=ULONG_MAX ) m = steady_idx[ steady_partner[ i ] ];
            if( steady_mode[ i ]==SMT_HALF ) s = ULONG_MAX;
          }
        } else if( e++>=ew ) { /* paired with the next execle */
          for( ulong k=j+1UL; k<topo->tile_cnt && m==ULONG_MAX; k++ ) if( topo->tiles[ k ].cpu_idx==ULONG_MAX && !strcmp( topo->tiles[ k ].name, "execle" ) ) m = k;
          if( m==ULONG_MAX || s==ULONG_MAX ) s = m = ULONG_MAX;
          e += (ulong)( m!=ULONG_MAX );
        }
        tile->cpu_idx = c;
        cpu_bv_insert( cpu_assigned, c );
        if( g ) cpu_bv_insert( group_post, c );
        if( s==ULONG_MAX ) continue;
        cpu_bv_insert( cpu_assigned, s );
        if( m!=ULONG_MAX ) topo->tiles[ m ].cpu_idx = s;
        if( g && ( m==ULONG_MAX || ( fd_topob_tile_class( topo->tiles[ m ].name ) & FD_TOPOB_TILE_POSTSTART ) ) ) cpu_bv_insert( group_post, s );
      }
    }
    if( !graded ) break;
    cpu_bv_subtract( cpu_assigned, cpu_assigned, numa_fence );
    cpu_bv_new( numa_fence );
  }

  if( FD_UNLIKELY( l3_layout ) ) {
    ulong hot_l3 = ULONG_MAX;
    for( char const ** p = HOT_TILES; *p; p++ ) {
      for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
        fd_topo_tile_t * tile = &topo->tiles[ j ];
        if( tile_is_floating( tile ) || strcmp( tile->name, *p ) ) continue;
        auto_tile_cpu_l3( tile, cpus, &hot_l3, cpu_assigned, cpu_ordering, dem );
      }
    }
  }

  /* First, assign always-on tiles */
  ulong cpu_idx = 0UL;
  if( graded ) smt_place( topo, cpus, cpu_assigned, cpu_ordering, steady_idx, 0UL, always_cnt, steady_cnt, steady_mode, steady_partner, efficient );
  for( ulong r=0UL; r<TILE_CLASS_CNT && !graded; r++ ) {
    if( !( TILE_CLASS[ r ].flags & FD_TOPOB_TILE_ALWAYS ) ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( tile_is_floating( tile ) || tile->cpu_idx!=ULONG_MAX || strcmp( tile->name, TILE_CLASS[ r ].name ) ) continue;
      auto_tile_cpu( tile, cpus, &cpu_idx, cpu_assigned, cpu_ordering, skip_ht_pairs, &spare_siblings, efficient, dem, 0UL );
    }
  }
  ulong cpu_idx_startup = cpu_bv_is_null( group_post ) ? cpu_idx : 0UL; /* may reuse group post-start cores */
  cpu_bv_t cpu_assigned_startup[ cpu_bv_word_cnt ];
  cpu_bv_subtract( cpu_assigned_startup, cpu_assigned, numa_fence );
  cpu_bv_subtract( cpu_assigned_startup, cpu_assigned_startup, group_post );
  ulong dem_startup[ 9 ] = { 0UL, 0UL, 0UL, dem[ 3 ], dem[ 4 ], dem[ 5 ], 0UL, 0UL, 0UL };
  dem[ 3 ] = dem[ 4 ] = dem[ 5 ] = 0UL;

  /* Separately assign startup and post-start tiles */
  for( ulong r=0UL; r<TILE_CLASS_CNT && !graded; r++ ) {
    if( !( TILE_CLASS[ r ].flags & FD_TOPOB_TILE_STARTUP ) ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( tile_is_floating( tile ) || strcmp( tile->name, TILE_CLASS[ r ].name ) ) continue;
      auto_tile_cpu( tile, cpus, &cpu_idx_startup, cpu_assigned_startup, cpu_ordering, skip_ht_pairs, &spare_siblings, efficient, dem_startup, 1UL );
    }
  }
  if( graded ) smt_place( topo, cpus, cpu_assigned, cpu_ordering, steady_idx, always_cnt, steady_cnt, steady_cnt, steady_mode, steady_partner, efficient );
  if( graded ) {
    cpu_bv_subtract( cpu_assigned, cpu_assigned, numa_fence );
    auto_startup_cpus( topo, cpus, cpu_assigned_startup, cpu_ordering, efficient );
  }
  for( ulong r=0UL; r<TILE_CLASS_CNT && !graded; r++ ) {
    if( !( TILE_CLASS[ r ].flags & FD_TOPOB_TILE_POSTSTART ) ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( tile->cpu_idx!=ULONG_MAX || strcmp( tile->name, TILE_CLASS[ r ].name ) ) continue;
      auto_tile_cpu( tile, cpus, &cpu_idx, cpu_assigned, cpu_ordering, skip_ht_pairs, &spare_siblings, efficient, dem, 2UL );
    }
  }

  /* Make sure all the tiles we haven't set are supposed to be floating. */
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( tile->cpu_idx!=ULONG_MAX ) continue;

    if( FD_UNLIKELY( !tile_is_floating( tile ) ) ) FD_LOG_WARNING(( "auto layout cannot affine tile `%s:%lu` because it is unknown. Leaving it floating", tile->name, tile->kind_id ));
  }

}

void
fd_topob_auto_layout( fd_topo_t * topo ) {
  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );
  fd_topob_auto_layout_cpus( topo, cpus );
}
