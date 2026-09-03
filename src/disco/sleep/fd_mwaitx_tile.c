/* The mwaitx tile converts doorbell rings into futex wakes: it naps in
   hardware wake-on-store on the doorbell cache line (umonitor/umwait
   on Intel, monitorx/mwaitx on AMD, pause spin fallback), and is the
   sole issuer of FUTEX_WAKE in the system.  It also services parked
   tiles' deadlines and runs the verifying sweep (seq_mirror vs
   seq_snap) that bounds any lost doorbell to ~one nap.  See
   fd_sleep.h. */

#include "fd_sleep.h"

#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"

#if FD_HAS_X86
#include <cpuid.h>
#endif

#include <linux/futex.h>

#include "generated/fd_mwaitx_tile_seccomp.h"

#define MWAITX_NAP_TICKS (100000L) /* ~30us at 3GHz; Intel caps umwait residency anyway */

struct fd_mwaitx_tile {
  fd_sleep_t * sleep;

  ulong tile_cnt;

  int has_waitpkg;
  int has_mwaitx;

  /* polled in link ids per tile, for the verifying sweep */
  uint  in_cnt [ FD_SLEEP_TILE_MAX ];
  uint  in_link[ FD_SLEEP_TILE_MAX ][ FD_SLEEP_IN_MAX ];

  ulong metrics_nap;
  ulong metrics_wake;
  ulong metrics_deadline;
  ulong metrics_sweep;
};

typedef struct fd_mwaitx_tile fd_mwaitx_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_mwaitx_tile_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_mwaitx_tile_t);
}

static void
metrics_write( fd_mwaitx_tile_t * ctx ) {
  FD_MCNT_SET( MWAITX, NAP,           ctx->metrics_nap      );
  FD_MCNT_SET( MWAITX, WAKE_ISSUED,   ctx->metrics_wake     );
  FD_MCNT_SET( MWAITX, DEADLINE_WAKE, ctx->metrics_deadline );
  FD_MCNT_SET( MWAITX, SWEEP_WAKE,    ctx->metrics_sweep    );
}

#if FD_HAS_X86

__attribute__((target("waitpkg"))) static inline void
idle_umwait( void const * line,
             long         deadline_tsc ) {
  __builtin_ia32_umonitor( (void *)line );
  __builtin_ia32_umwait( 0U /* C0.2 */, (unsigned long long)deadline_tsc );
}

__attribute__((target("mwaitx"))) static inline void
idle_mwaitx( void const * line,
             long         nap_ticks ) {
  __builtin_ia32_monitorx( (void *)line, 0U, 0U );
  __builtin_ia32_mwaitx( 0x2U /* timer */, 0x0U /* C1 */, (unsigned)nap_ticks );
}

#endif

/* idle_wait naps until a store lands on the doorbell line or the nap
   deadline passes.  Falls back to a bounded pause spin on CPUs with
   neither WAITPKG nor MWAITX: correct, just no power saving here. */

static inline void
idle_wait( fd_mwaitx_tile_t * ctx ) {
  ulong const * line = ctx->sleep->doorbell;
  long deadline = fd_tickcount()+MWAITX_NAP_TICKS;
#if FD_HAS_X86
  if( FD_LIKELY( ctx->has_waitpkg ) ) { idle_umwait( line, deadline );        return; }
  if( FD_LIKELY( ctx->has_mwaitx  ) ) { idle_mwaitx( line, MWAITX_NAP_TICKS ); return; }
#endif
  ulong seen = FD_VOLATILE_CONST( line[0] );
  while( FD_LIKELY( fd_tickcount()<deadline ) ) {
    if( FD_UNLIKELY( FD_VOLATILE_CONST( line[0] )!=seen ) ) break;
    FD_SPIN_PAUSE();
  }
}

static void
before_credit( fd_mwaitx_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  fd_sleep_t * sleep = ctx->sleep;

  idle_wait( ctx );
  ctx->metrics_nap++;

  long now = fd_tickcount();

  for( ulong w=0UL; w<FD_SLEEP_BITS_CNT; w++ ) {
    /* snapshot-and-clear: a plain read-then-write would drop
       concurrent rings */
    ulong rung = FD_VOLATILE_CONST( sleep->doorbell[ w ] );
    if( FD_UNLIKELY( rung ) ) rung = __atomic_exchange_n( &sleep->doorbell[ w ], 0UL, __ATOMIC_ACQUIRE );

    ulong parked = FD_VOLATILE_CONST( sleep->parked_bits[ w ] );

    /* Rung tiles are woken even if their parked bit is not (yet)
       visible: a wake to a running tile is a harmless store, and this
       closes the ring-vs-park visibility race.  Parked-but-unrung
       tiles get deadline service and the verifying sweep. */
    ulong check = rung | parked;
    while( check ) {
      ulong bit = check & (~check+1UL);
      ulong tid = (w<<6) + (ulong)fd_ulong_find_lsb( check );
      check ^= bit;

      if( !(rung & bit) ) {
        /* timer service */
        if( FD_UNLIKELY( (long)FD_VOLATILE_CONST( sleep->tile[ tid ].deadline )<=now ) ) {
          rung |= bit;
          ctx->metrics_deadline++;
        } else {
          /* verifying sweep: producer mirror ahead of the parked
             tile's snapshot = a pending frag whose doorbell was lost
             or raced (the bounded SB window).  Nonzero at a low rate
             is expected and healthy. */
          for( ulong i=0UL; i<(ulong)ctx->in_cnt[ tid ]; i++ ) {
            ulong mirror = FD_VOLATILE_CONST( sleep->seq_mirror[ ctx->in_link[ tid ][ i ] ] );
            if( FD_UNLIKELY( fd_seq_lt( FD_VOLATILE_CONST( sleep->seq_snap[ tid ][ i ] ), mirror ) ) ) {
              rung |= bit;
              ctx->metrics_sweep++;
              break;
            }
          }
        }
      }

      if( FD_UNLIKELY( (rung & bit) ) ) {
        fd_sleep_wake_one( &sleep->tile[ tid ].word );
        ctx->metrics_wake++;
        *charge_busy = 1;
      }
    }
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_mwaitx_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_mwaitx_tile_t), sizeof(fd_mwaitx_tile_t) );

  ctx->sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
  FD_TEST( ctx->sleep );
  ctx->tile_cnt = topo->tile_cnt;

  for( ulong i=0UL; i<FD_SLEEP_TILE_MAX; i++ ) ctx->in_cnt[ i ] = 0U;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * t = &topo->tiles[ i ];
    if( FD_UNLIKELY( !fd_sleep_tile_parks( t->name ) ) ) continue;
    ulong polled = 0UL;
    for( ulong j=0UL; j<t->in_cnt; j++ ) {
      if( FD_UNLIKELY( !t->in_link_poll[ j ] ) ) continue;
      ctx->in_link[ t->id ][ polled++ ] = (uint)t->in_link_id[ j ];
    }
    ctx->in_cnt[ t->id ] = (uint)polled;
  }

  ctx->has_waitpkg = 0;
  ctx->has_mwaitx  = 0;
#if FD_HAS_X86
  uint eax, ebx, ecx, edx;
  if( FD_LIKELY( __get_cpuid_count( 7U, 0U, &eax, &ebx, &ecx, &edx ) ) ) ctx->has_waitpkg = !!(ecx & (1U<<5U));
  if( FD_LIKELY( __get_cpuid( 0x80000001U, &eax, &ebx, &ecx, &edx ) ) ) ctx->has_mwaitx  = !!(ecx & (1U<<29U));
#endif

  ctx->metrics_nap      = 0UL;
  ctx->metrics_wake     = 0UL;
  ctx->metrics_deadline = 0UL;
  ctx->metrics_sweep    = 0UL;

  if( FD_UNLIKELY( !ctx->has_waitpkg && !ctx->has_mwaitx ) ) FD_LOG_WARNING(( "CPU has neither WAITPKG nor MWAITX; mwaitx tile will spin (no power saving on its core)" ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_mwaitx_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_mwaitx_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_mwaitx_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_mwaitx_tile_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_METRICS_WRITE metrics_write

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_mwaitx = {
  .name                     = "mwaitx",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
