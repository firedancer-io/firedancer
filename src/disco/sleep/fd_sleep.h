#ifndef HEADER_fd_src_disco_sleep_fd_sleep_h
#define HEADER_fd_src_disco_sleep_fd_sleep_h

/* Idle tiles park in futex_wait instead of spinning and are woken in
   microseconds when work arrives.  Three roles share one shmem region:

     sleeper   a stem tile with no work: flushes its link state, sets
               its bit in parked_bits, re-checks its ins once under the
               RMW fence, then FUTEX_WAIT_BITSETs on its word with an
               absolute deadline.

     producer  on publish: load parked_bits[w] & a mask precomputed at
               boot; if nonzero, locked OR into doorbell[w].  Never a
               syscall.

     mwaitx    naps in hardware on the doorbell line (umwait/mwaitx),
               turns rung bits into FUTEX_WAKEs, and runs the verifying
               sweep (seq_mirror vs seq_snap) that bounds a lost
               doorbell to one nap.  The only FUTEX_WAKE issuer.

   word 0 = parked, nonzero = running.  The doorbell is a hint: truth
   is level triggered (seqs, deadline) and re-checked on every wake,
   so spurious wakes are absorbed and a lost hint costs only bounded
   latency (the sweep, then the tile's own deadline). */

#include "../../util/fd_util_base.h"

#define FD_SLEEP_ALIGN     (128UL)
#define FD_SLEEP_MAGIC     (0xf17eda2c3751ee90UL) /* firedancer sleep ver 0 */

#define FD_SLEEP_TILE_MAX  (512UL)
#define FD_SLEEP_BITS_CNT  (FD_SLEEP_TILE_MAX/64UL)
#define FD_SLEEP_LINK_MAX  (256UL) /* ==FD_TOPO_MAX_LINKS  */
#define FD_SLEEP_IN_MAX    (128UL) /* ==FD_TOPO_MAX_TILE_IN_LINKS */

#define FD_SLEEP_LINGER_NS   (0L)        /* park as soon as caught up */
#define FD_SLEEP_PARK_CAP_NS (20000000L) /* longest park */

struct __attribute__((aligned(FD_SLEEP_ALIGN))) fd_sleep_private {
  /* Loaded on every publish, written only at park/unpark */
  ulong parked_bits[ FD_SLEEP_BITS_CNT ];
  ulong magic; /* ==FD_SLEEP_MAGIC, off the parked_bits line */
  ulong pad0[ 7 ];

  /* Locked OR on wake edges; the line mwaitx monitors.  Own line. */
  ulong doorbell[ FD_SLEEP_BITS_CNT ];
  ulong pad1[ 8 ];

  /* Indexed by tile->id; written by the owner and mwaitx only */
  struct __attribute__((aligned(64UL))) {
    ulong word;      /* futex word: 0 parked, 1 running */
    ulong gen;       /* park count, diagnostics */
    ulong deadline;  /* abs fd_tickcount of the next timed obligation */
    ulong pad[ 5 ];
  } tile[ FD_SLEEP_TILE_MAX ];

  /* Sweep state: producers mirror out seqs at housekeeping, a parking
     tile snapshots the next seq it expects per polled in.
     mirror[link]>snap means a frag is pending. */
  ulong seq_mirror[ FD_SLEEP_LINK_MAX ];
  ulong seq_snap[ FD_SLEEP_TILE_MAX ][ FD_SLEEP_IN_MAX ];
};

typedef struct fd_sleep_private fd_sleep_t;

/* Wake table entry: the consumers of one out link as a (bitmap word,
   mask) pair.  One pair per link in practice. */

struct fd_sleep_wake {
  ulong w;
  ulong mask;
};

typedef struct fd_sleep_wake fd_sleep_wake_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong fd_sleep_align    ( void );
FD_FN_CONST ulong fd_sleep_footprint( void );

/* fd_sleep_new formats shmem (fd_sleep_align aligned, fd_sleep_footprint
   bytes) as a sleep region with every tile running.  Returns shmem on
   success, NULL on failure (logs details). */

void *       fd_sleep_new   ( void *             shmem   );
fd_sleep_t * fd_sleep_join  ( void *             shsleep );

/* fd_sleep_ring marks tile_id as having work.  Safe from any thread;
   ringing a running tile is harmless. */

static inline void
fd_sleep_ring( fd_sleep_t * sleep,
               ulong              tile_id ) {
  __atomic_fetch_or( &sleep->doorbell[ tile_id>>6 ], 1UL<<(tile_id&63UL), __ATOMIC_RELEASE );
}

/* fd_sleep_wake_check rings the parked consumers of one out link.
   One load per pair; the locked OR only on a hit. */

static inline void
fd_sleep_wake_check( fd_sleep_t *      sleep,
                     fd_sleep_wake_t const * wake,
                     ulong                   wake_cnt ) {
  for( ulong k=0UL; k<wake_cnt; k++ ) {
    ulong rung = FD_VOLATILE_CONST( sleep->parked_bits[ wake[ k ].w ] ) & wake[ k ].mask;
    if( FD_UNLIKELY( rung ) ) __atomic_fetch_or( &sleep->doorbell[ wake[ k ].w ], rung, __ATOMIC_RELEASE );
  }
}

/* fd_sleep_tile_parks returns 1 if the named tile parks when idle.
   sock/mlx5 need their own event-mode analysis, the waker blocks in
   epoll, mwaitx naps in hardware.  Non-parking tiles still ring
   doorbells as producers. */

static inline int
fd_sleep_tile_parks( char const * name ) {
  return strcmp( name, "sock"  ) &&
         strcmp( name, "mlx5"  ) &&
         strcmp( name, "waker" ) &&
         strcmp( name, "mwaitx" );
}

/* Unpark causes, in ParkWake metrics enum order */

#define FD_SLEEP_UNPARK_RING     (0)
#define FD_SLEEP_UNPARK_DEADLINE (1)
#define FD_SLEEP_UNPARK_PENDING  (2)

/* fd_sleep_park_wait blocks on word (caller set it to 0) until woken
   or deadline_ticks (abs fd_tickcount) passes.  Returns the cause.
   fd_sleep_wake_one sets word to 1 and wakes one waiter; called by
   the mwaitx tile only. */

int  fd_sleep_park_wait( ulong * word, long deadline_ticks );
void fd_sleep_wake_one ( ulong * word );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_sleep_fd_sleep_h */
