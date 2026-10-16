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
  { "resolh", ALWAYS                       }, /* FRANK only */
  { "resolv", ALWAYS                       }, /* FIREDANCER only */
  { "pack",   ALWAYS|CRITICAL              },
  { "bank",   ALWAYS                       }, /* FRANK only */
  { "pohh",   ALWAYS|CRITICAL              }, /* FRANK only */
  { "sign",   ALWAYS                       },
  { "shred",  ALWAYS                       },
  { "event",  ALWAYS                       }, /* FIREDANCER only */
  { "store",  ALWAYS                       }, /* FRANK only */
  { "plugin", ALWAYS                       }, /* FRANK only */
  { "gui",    ALWAYS                       }, /* FIREDANCER only */
  { "guih",   ALWAYS                       }, /* FRANK only */
  { "rpc",    ALWAYS                       }, /* FIREDANCER only */
  { "gossvf", ALWAYS                       }, /* FIREDANCER only */
  { "gossip", ALWAYS                       }, /* FIREDANCER only */
  { "repair", ALWAYS                       }, /* FIREDANCER only */
  { "rotor",  ALWAYS                       }, /* FIREDANCER only */
  { "rserve", ALWAYS                       }, /* FIREDANCER only */
  { "replay", ALWAYS|THRUPUT               }, /* FIREDANCER only */
  { "tower",  ALWAYS                       }, /* FIREDANCER only */
  { "votor",  ALWAYS                       }, /* FIREDANCER only */
  { "pktgen", ALWAYS                       },
  { "mwaitx", ALWAYS|PIN_EFF               }, /* FIREDANCER only */

  /* Must shut down after snapshot load */
  { "snapct", STARTUP                      }, /* FIREDANCER only */
  { "snapld", STARTUP                      }, /* FIREDANCER only */
  { "snapdc", STARTUP|THRUPUT              }, /* FIREDANCER only */
  { "snapin", STARTUP|THRUPUT              }, /* FIREDANCER only */

  /* Must sleep until snapshot load finishes */
  { "accdb",  POSTSTART|THRUPUT            }, /* FIREDANCER only */
  { "execle", POSTSTART|THRUPUT            }, /* FIREDANCER only */
  { "poh",    POSTSTART|CRITICAL           }, /* FIREDANCER only */
  { "motor",  POSTSTART|CRITICAL           }, /* FIREDANCER only */
  { "execrp", POSTSTART|DEDICATED|THRUPUT  }, /* FIREDANCER only */
  { "txsend", POSTSTART                    }, /* FIREDANCER only */
  { "solcap", POSTSTART|PIN_EFF            }, /* FIREDANCER only */

  /* Yield to the kernel scheduler */
  { "netlnk", FLOATING                     },
  { "metric", FLOATING                     },
  { "diag",   FLOATING                     },
  { "waker",  FLOATING                     },
  { "bencho", FLOATING                     },
  { "l4swap", FLOATING                     },
  { "genesi", FLOATING                     }, /* FIREDANCER only */
  { "ipecho", FLOATING                     }, /* FIREDANCER only */
  { "admin",  FLOATING                     }, /* FIREDANCER only */
  { "snapsv", FLOATING|PIN_EFF             }, /* FIREDANCER only */
  { "snapmk", FLOATING                     }, /* FIREDANCER only */
  { "snapzp", FLOATING                     }, /* FIREDANCER only */
  { "snaprd", FLOATING                     }, /* FIREDANCER only */
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
  "mwaitx", /* FIREDANCER only */
  "replay", /* FIREDANCER only */
  "execrp", /* FIREDANCER only */
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

void
fd_topob_auto_layout_cpus( fd_topo_t *      topo,
                           fd_topo_cpus_t * cpus,
                           int              reserve_agave_cores ) {
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
  int l3_layout = efficient && !reserve_agave_cores && fd_topo_cpus_l3_complete( cpus ) &&
                  available_physical>=l3_tiles_to_assign && available_floater>=l3_floaters_to_assign;

  /* If we have enough physical cores (excluding HT siblings) for all
     tiles that need assignment, exclude HT siblings so that no tile
     gets scheduled on a hyperthread pair.
     For Frankendancer, we reserve 2x cores so we have enough for Agave */
  _Bool skip_ht_pairs = reserve_agave_cores
    ? (available_physical>=2*tiles_to_assign) /* Frankendancer */
    : (available_physical>=tiles_to_assign && ( !efficient || available_floater>=floaters_to_assign )); /* Firedancer */

  /* Otherwise spend the spare logical CPUs on whole cores for the
     dedicated tiles.  Each costs its sibling, like a critical tile.
     The L3 layout already places them on whole cores. */
  ulong spare_siblings = 0UL;
  if( !skip_ht_pairs && !l3_layout && !reserve_agave_cores ) {
    ulong free_logical = 0UL;
    for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) free_logical += !cpu_bv_test( cpu_assigned, i );
    ulong critical_cnt = 0UL;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) critical_cnt += (ulong)!!( fd_topob_tile_class( topo->tiles[ j ].name ) & FD_TOPOB_TILE_SMT_CRITICAL );
    spare_siblings = fd_ulong_sat_sub( free_logical, tiles_to_assign+critical_cnt );
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
  for( ulong r=0UL; r<TILE_CLASS_CNT; r++ ) {
    if( !( TILE_CLASS[ r ].flags & FD_TOPOB_TILE_ALWAYS ) ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( tile_is_floating( tile ) || tile->cpu_idx!=ULONG_MAX || strcmp( tile->name, TILE_CLASS[ r ].name ) ) continue;
      auto_tile_cpu( tile, cpus, &cpu_idx, cpu_assigned, cpu_ordering, skip_ht_pairs, &spare_siblings, efficient, dem, 0UL );
    }
  }
  ulong cpu_idx_startup = cpu_idx;
  cpu_bv_t cpu_assigned_startup[ cpu_bv_word_cnt ];
  cpu_bv_copy( cpu_assigned_startup, cpu_assigned );
  ulong dem_startup[ 9 ] = { 0UL, 0UL, 0UL, dem[ 3 ], dem[ 4 ], dem[ 5 ], 0UL, 0UL, 0UL };
  dem[ 3 ] = dem[ 4 ] = dem[ 5 ] = 0UL;

  /* Separately assign startup and post-start tiles */
  for( ulong r=0UL; r<TILE_CLASS_CNT; r++ ) {
    if( !( TILE_CLASS[ r ].flags & FD_TOPOB_TILE_STARTUP ) ) continue;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) {
      fd_topo_tile_t * tile = &topo->tiles[ j ];
      if( tile_is_floating( tile ) || strcmp( tile->name, TILE_CLASS[ r ].name ) ) continue;
      auto_tile_cpu( tile, cpus, &cpu_idx_startup, cpu_assigned_startup, cpu_ordering, skip_ht_pairs, &spare_siblings, efficient, dem_startup, 1UL );
    }
  }
  for( ulong r=0UL; r<TILE_CLASS_CNT; r++ ) {
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

  topo->agave_affinity_cnt = 0UL;
  if( FD_UNLIKELY( reserve_agave_cores ) ) {
    for( ulong i=cpu_idx; i<cpus->cpu_cnt; i++ ) {
      if( FD_UNLIKELY( !cpus->cpu[ cpu_ordering[ i ] ].online ) ) continue;
      if( FD_UNLIKELY( cpu_bv_test( cpu_assigned, cpu_ordering[ i ] ) ) ) continue;

      if( FD_LIKELY( topo->agave_affinity_cnt<sizeof(topo->agave_affinity_cpu_idx)/sizeof(topo->agave_affinity_cpu_idx[0]) ) ) {
        topo->agave_affinity_cpu_idx[ topo->agave_affinity_cnt++ ] = cpu_ordering[ i ];
      }
    }
  }
}

void
fd_topob_auto_layout( fd_topo_t * topo,
                      int         reserve_agave_cores ) {
  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );
  fd_topob_auto_layout_cpus( topo, cpus, reserve_agave_cores );
}
