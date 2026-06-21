#ifndef HEADER_fd_src_waltz_slow_fd_wheel_h
#define HEADER_fd_src_waltz_slow_fd_wheel_h

/* fd_wheel.h is a scalable timer heap for QUIC connections.

   Uses a hierarchical "hashed" separately chained timer wheel.
   (There is no hashing but it is structurally similar to a hash map.)
   Designed to be used with unix epoch nanosecond timestamps (e.g.
   fd_log_wallclock() or fd_clock_tile_now()).

   fd_wheel expires all timers in place and does not cascade.  Timers
   often expire late but never early.  The max expiry delay of a timer
   is the the tick size of the level the timer was installed into.

   FIXME ... this causes network-wide random bursts, introduce a
   constant random bias ...

   (e.g. a timer expiring in 100 ms is installed in L2, remains there
   until removal or expiration, and may expire up to 524 µs late.) */

#include "../../util/bits/fd_bits.h"

/* The following are hardcoded wheel timing parameters.
   The levels were hand-tuned to perform well for a QUIC client in
   Europe connecting to all staked Solana mainnet nodes (Jun 2026).

   | Lvl | Window                 | Tick    |
   |-----|------------------------|---------|
   | L0  | [    0 ms,    1.05 ms) |    2 µs |
   | L1  | [ 1.05 ms,   16.8  ms) |   33 µs |
   | L2  | [16.8  ms,  268    ms) |  524 µs |
   | L3  | [268   ms, 4300    ms) | 8389 µs | */

#define FD_WHEEL_LG_BUCKET_CNT  9
#define FD_WHEEL_LEVEL_CNT      4
#define FD_WHEEL_LG_GRANULE    11
#define FD_WHEEL_LG_STEP        4

/* FD_WHEEL_SHIFT gives the exponent x for a given level, such that
   2^x gives the nanosecond range covering a bucket at that level.

   FD_WHEEL_BUCKET gives the nanosecond range of a bucket at the given
   level.

   FD_WHEEL_RANGE gives the nanosecond range between the wheel's
   timestamp base and the highest bucket (included).

   FD_WHEEL_SLOT gives the bucket index for a given timestamp and
   wheel level in [0,FD_WHEEL_BUCKET_CNT). */

#define FD_WHEEL_BUCKET_CNT   (1U<<FD_WHEEL_LG_BUCKET_CNT)
#define FD_WHEEL_SHIFT(lvl)   (FD_WHEEL_LG_GRANULE+(lvl)*FD_WHEEL_LG_STEP)
#define FD_WHEEL_BUCKET(lvl)  (1L<<FD_WHEEL_SHIFT( lvl ))
#define FD_WHEEL_RANGE(lvl)   (((long)FD_WHEEL_BUCKET_CNT)<<FD_WHEEL_SHIFT( lvl ))
#define FD_WHEEL_SLOT(lvl,ts) (((ts)>>FD_WHEEL_SHIFT( lvl )) & (FD_WHEEL_BUCKET_CNT-1))

/* fd_wheel_timer_t is a timer object.  Timer objects are created by the
   API user and then moved in/out of the wheel using the below APIs.

   While a timer object is owned by a wheel object, the timer's shared
   fields are managed by the wheel object (prev/next links together
   timers that expire at the same time). */

struct __attribute__((aligned(32))) fd_wheel_timer {
  /* shared fields */
  uint  prev;
  uint  next;
  long  deadline;
  /* caller owned fields */
  ulong dcid;
  ulong pktnum : 60;
  ulong level : 2;
  ulong timer : 2;
};

typedef struct fd_wheel_timer fd_wheel_timer_t;

FD_STATIC_ASSERT( alignof(fd_wheel_timer_t)==32, layout );
FD_STATIC_ASSERT( sizeof (fd_wheel_timer_t)==32, layout );

/* fd_wheel_t tracks timers with upcoming expirations.

   Conceptually, the wheel has FD_WHEEL_LEVEL_CNT*FD_WHEEL_BUCKET_CNT
   time windows. */

struct fd_wheel {
  uint map[ FD_WHEEL_LEVEL_CNT ][ FD_WHEEL_BUCKET_CNT ];

  fd_wheel_timer_t * pool;
  long               base;
};

typedef struct fd_wheel fd_wheel_t;

FD_PROTOTYPES_BEGIN

/* fd_wheel_new creates a new wheel object at *wheel.  For the lifetime
   of the wheel it is bound to one object pool.  pool points to timer
   index 0 of the object pool, with up to UINT_MAX addressable timer
   elements.  now is a hint for the initial wheel time base (0L is fine,
   fd_log_wallclock() is ideal). */

fd_wheel_t *
fd_wheel_new( fd_wheel_t *       wheel,
              fd_wheel_timer_t * pool,
              long               now );

/* fd_wheel_delete destroys the wheel object and returns the underlying
   memory region back to the caller.  Releases ownership of all timer
   objects that were in the pool (but without updating prev/next links). */

void *
fd_wheel_delete( fd_wheel_t * wheel );

/* fd_wheel_range returns the nanosecond range covered by the timer
   wheel (across all levels). */

FD_FN_CONST static inline long
fd_wheel_range( void ) {
  return FD_WHEEL_RANGE( FD_WHEEL_LEVEL_CNT-1 );
}

/* fd_wheel_insert_is_safe confirms the expiration behavior of a timer
   inserted with the given deadline.  Invalidated by operations that
   move the wheel base.

   Return value:
   0 -> timer will expire arbitrarily early or late
   1 -> timers at least 30µs in the future expire at most ~3.3% late,
        but never too early */

FD_FN_PURE static inline int
fd_wheel_insert_is_safe( fd_wheel_t const * wheel,
                         long               deadline ) {
  long base = wheel->base;
  return deadline >= base && deadline <  base + fd_wheel_range();
}

/* fd_wheel_insert inserts the timer into the wheel.  Moves ownership
   of the timer object to the wheel.  U.B. if the same object is
   inserted more than once without removing it first. */

void
fd_wheel_insert( fd_wheel_t *       wheel,
                 fd_wheel_timer_t * timer );

/* fd_wheel_remove removes the given timer from the wheel and returns
   timer.  Moves ownership of the timer obejct to the caller.
   U.B. if the timer is not currently in the wheel (e.g. because it
        was just removed, or was given to the caller during advance()). */

fd_wheel_timer_t *
fd_wheel_remove( fd_wheel_t *       wheel,
                 fd_wheel_timer_t * timer );

/* fd_wheel_advance calls cb for every expired timer.  If cb is a static
   function, the compiler is typically able to inline it.

   Ownership of each timer delivered moves to the callee (which, e.g.,
   frees the timer object).  cb may not insert or remove timers. */

static inline __attribute__((always_inline)) void
fd_wheel_advance( fd_wheel_t * wheel,
                  long         now,
                  void (* cb)( void *             ctx,
                               fd_wheel_timer_t * timer ),
                  void * cb_ctx ) {
  now = (long)fd_ulong_align_dn( (ulong)now, (ulong)FD_WHEEL_BUCKET( 0 ) );
  long base = wheel->base;
  wheel->base = now;
  for( uint lvl=0U; lvl<FD_WHEEL_LEVEL_CNT; lvl++ ) {
    long bucket = FD_WHEEL_BUCKET( lvl );
    long cur    = (long)fd_ulong_align_dn( (ulong)base, (ulong)bucket );
    long thres  = cur + bucket;
    if( now<thres ) continue;
    uint cnt = (uint)( ((now-thres) >> FD_WHEEL_SHIFT( lvl )) + 1L );
    cnt = fd_uint_min( cnt, FD_WHEEL_BUCKET_CNT );
    for( uint i=0U; i<cnt; i++ ) {
      uint slot = FD_WHEEL_SLOT( lvl, cur );
      uint idx  = wheel->map[ lvl ][ slot ];
      wheel->map[ lvl ][ slot ] = UINT_MAX;
      while( idx!=UINT_MAX ) {
        fd_wheel_timer_t * timer = &wheel->pool[ idx ];
        uint next = timer->next;
        cb( cb_ctx, timer );
        idx = next;
      }
      cur += bucket;
    }
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_slow_fd_wheel_h */
