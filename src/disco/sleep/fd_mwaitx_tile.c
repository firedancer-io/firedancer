/* The mwaitx tile converts doorbell rings into futex wakes: it naps in
   hardware wake-on-store on the doorbell cache line (umonitor/umwait
   on Intel, monitorx/mwaitx on AMD, pause spin fallback), and is the
   sole issuer of FUTEX_WAKE in the system.  It also services parked
   tiles' deadlines and runs the verifying sweep (seq_mirror vs
   seq_snap) that bounds any lost doorbell to ~one nap. */

#include "fd_sleep.h"

#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"

#if FD_HAS_X86
#include <cpuid.h>
#include <x86intrin.h>
#endif

#include <linux/futex.h>

#include "generated/fd_mwaitx_tile_seccomp.h"

#define MWAITX_NAP_TICKS (100000L) /* ~30us at 3GHz, Intel caps umwait residency anyway */

struct fd_mwaitx_tile {
  fd_sleep_t * sleep;

  ulong tile_cnt;

  int has_waitpkg;
  int has_mwaitx;

  /* polled in link ids per tile, for the verifying sweep */
  uint  in_cnt [ FD_SLEEP_TILE_MAX ];
  uint  in_link[ FD_SLEEP_TILE_MAX ][ FD_SLEEP_IN_MAX ];

  long  next_sweep; /* tick of the next deadline/sweep pass */

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

static inline int
doorbell_rung( ulong const * line ) {
  ulong any = 0UL;
  for( ulong w=0UL; w<FD_SLEEP_BITS_CNT; w++ ) any |= FD_VOLATILE_CONST( line[ w ] );
  return !!any;
}

#if FD_HAS_X86

__attribute__((target("waitpkg"))) static inline void
idle_umwait( ulong const * line,
             long          deadline_tsc ) {
  _umonitor( (void *)line );
  if( FD_UNLIKELY( doorbell_rung( line ) ) ) return;
  _umwait( 0U /* C0.2 */, (unsigned long long)deadline_tsc );
}

__attribute__((target("mwaitx"))) static inline void
idle_mwaitx( ulong const * line,
             long          nap_ticks ) {
  _mm_monitorx( (void *)line, 0U, 0U );
  if( FD_UNLIKELY( doorbell_rung( line ) ) ) return;
  _mm_mwaitx( 0x2U /* timer */, 0x0U /* C1 */, (unsigned)nap_ticks );
}

#endif

static void
before_credit( fd_mwaitx_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  long now = fd_tickcount();

  /* Nap until a store lands on the doorbell line or the nap deadline
     passes. */
  long deadline = now+MWAITX_NAP_TICKS;
#if FD_HAS_X86
  if(      FD_LIKELY( ctx->has_waitpkg ) ) idle_umwait( ctx->sleep->doorbell, deadline );
  else if( FD_LIKELY( ctx->has_mwaitx  ) ) idle_mwaitx( ctx->sleep->doorbell, MWAITX_NAP_TICKS );
  else
#endif
  while( FD_LIKELY( fd_tickcount()<deadline ) ) {
    if( FD_UNLIKELY( doorbell_rung( ctx->sleep->doorbell ) ) ) break;
    FD_SPIN_PAUSE();
  }

  ctx->metrics_nap++;

  /* Nap ended ... send wakes if any first for latency.  No need to wake
     if already woken, and snapshot the parked bits to avoid races. */
  for( ulong w=0UL; w<FD_SLEEP_BITS_CNT; w++ ) {
    ulong rung = FD_VOLATILE_CONST( ctx->sleep->doorbell[ w ] );
    if( FD_LIKELY( !rung ) ) continue;

    rung = __atomic_exchange_n( &ctx->sleep->doorbell[ w ], 0UL, __ATOMIC_ACQUIRE );
    while( rung ) {
      ulong tid = (w<<6) + (ulong)fd_ulong_find_lsb( rung );
      rung &= rung-1UL;
      if( FD_LIKELY( !FD_VOLATILE_CONST( ctx->sleep->tile[ tid ].word ) ) ) {
        fd_sleep_wake_one( &ctx->sleep->tile[ tid ].word );
        ctx->metrics_wake++;
      }
      *charge_busy = 1;
    }
  }

  /* Every nap period, service tile deadlines, and sweep all parked
     tiles to catch any lost doorbells due to small unavoidable race
     windows in the read-then-park sequence. */

  if( FD_LIKELY( now<ctx->next_sweep ) ) return;
  ctx->next_sweep = now+MWAITX_NAP_TICKS;

  for( ulong w=0UL; w<FD_SLEEP_BITS_CNT; w++ ) {
    ulong parked = FD_VOLATILE_CONST( ctx->sleep->parked_bits[ w ] );
    while( parked ) {
      ulong tid = (w<<6) + (ulong)fd_ulong_find_lsb( parked );
      parked &= parked-1UL;
      if( FD_UNLIKELY( FD_VOLATILE_CONST( ctx->sleep->tile[ tid ].word ) ) ) continue; /* already woken */

      int wake = 0;
      if( FD_UNLIKELY( (long)FD_VOLATILE_CONST( ctx->sleep->tile[ tid ].deadline )<=now ) ) {
        wake = 1;
        ctx->metrics_deadline++;
      } else if( FD_LIKELY( !(FD_VOLATILE_CONST( ctx->sleep->credit_bits[ w ] ) & (1UL<<(tid&63UL))) ) ) {
        /* Producer mirror is ahead of the parked tile's snapshot, a
           pending frag is available, the doorbell was lost or raced.
           A tile parked on backpressure (credit bit) cannot use a
           frag; only its deadline or a credit ring wakes it. */
        for( ulong i=0UL; i<(ulong)ctx->in_cnt[ tid ]; i++ ) {
          ulong mirror = FD_VOLATILE_CONST( ctx->sleep->seq_mirror[ ctx->in_link[ tid ][ i ] ] );
          if( FD_UNLIKELY( fd_seq_lt( FD_VOLATILE_CONST( ctx->sleep->seq_snap[ tid ][ i ] ), mirror ) ) ) {
            wake = 1;
            ctx->metrics_sweep++;
            break;
          }
        }
      }

      if( FD_UNLIKELY( wake ) ) {
        fd_sleep_wake_one( &ctx->sleep->tile[ tid ].word );
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

  ctx->next_sweep       = 0L;
  ctx->metrics_nap      = 0UL;
  ctx->metrics_wake     = 0UL;
  ctx->metrics_deadline = 0UL;
  ctx->metrics_sweep    = 0UL;

  if( FD_UNLIKELY( !ctx->has_waitpkg && !ctx->has_mwaitx ) ) FD_LOG_WARNING(( "cpu has neither waitpkg nor mwaitx, mwaitx tile will spin" ));

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
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

#define STEM_NEVER_PARK 1
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
