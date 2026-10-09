#ifndef HEADER_fd_src_disco_sleep_fd_sleep_h
#define HEADER_fd_src_disco_sleep_fd_sleep_h

/* Idle tiles park in futex_wait instead of spinning and are woken
   when work arrives.  Three roles share one shmem region:

     sleeper   a stem tile with no work: flushes its link state, sets
               its bit in parked_bits, re-checks its ins once under the
               RMW fence, then FUTEX_WAIT_BITSETs on its word, timed
               only if a deadline is due before the park cap (the sweep
               enforces the cap).

     producer  on publish: full fence (StoreLoad, pairs with the
               sleeper's RMW), load parked_bits[w] & a mask precomputed
               at boot; if nonzero, locked OR into doorbell[w].

     mwaitx    naps in hardware on the doorbell line (umwait/mwaitx),
               turns rung bits into FUTEX_WAKEs, and runs the verifying
               sweep (seq_mirror vs seq_snap) that bounds a lost
               doorbell to one nap.  The only FUTEX_WAKE issuer.

   word 0 = parked, nonzero = running (the value says why).  The
   doorbell is a hint: truth is level triggered (seqs, deadline) and
   re-checked on every wake, so spurious wakes are absorbed and a lost
   hint costs only bounded latency (the sweep, then the tile's own
   deadline).

   A tile with its own kernel fds (tile->sleep_eventfd) parks in epoll
   instead, with an eventfd doorbell at FD_SLEEP_EVENTFD( id ) that
   mwaitx writes in place of FUTEX_WAKE. */

#include "../../util/fd_util_base.h"

#define FD_SLEEP_ALIGN     (128UL)
#define FD_SLEEP_MAGIC     (0xf17eda2c3751ee90UL) /* firedancer sleep ver 0 */

#define FD_SLEEP_TILE_MAX  ( 512UL)
#define FD_SLEEP_BITS_CNT  (FD_SLEEP_TILE_MAX/64UL)
#define FD_SLEEP_LINK_MAX  (1024UL) /* ==FD_TOPO_MAX_LINKS */
#define FD_SLEEP_IN_MAX    ( 256UL) /* ==FD_TOPO_MAX_TILE_IN_LINKS */
#define FD_SLEEP_OUT_MAX   (  64UL) /* ==FD_TOPO_MAX_TILE_OUT_LINKS */

#define FD_SLEEP_LINGER_NS   (0L)        /* park as soon as caught up */
#define FD_SLEEP_PARK_CAP_NS (20000000L) /* longest park */
#define FD_SLEEP_PARK_MIN_NS (5000L)     /* shorter than this and the futex round trip costs more than the spin */

/* Inherited fd number of a tile's eventfd doorbell */
#define FD_SLEEP_EVENTFD_BASE (123600)
#define FD_SLEEP_EVENTFD( id ) (FD_SLEEP_EVENTFD_BASE+(int)(id))

/* epoll data of the eventfd doorbell in a tile's park set */
#define FD_SLEEP_EPOLL_DOORBELL (ULONG_MAX)

struct __attribute__((aligned(FD_SLEEP_ALIGN))) fd_sleep_private {
  /* Loaded on every publish, written only at park/unpark */
  ulong parked_bits[ FD_SLEEP_BITS_CNT ];
  ulong  magic;       /* ==FD_SLEEP_MAGIC, off the parked_bits line */
  double tick_per_ns; /* fd_tickcount ticks per ns, for futex deadlines */
  ulong  pad0[ 6 ];

  /* Locked OR on wake edges; the line mwaitx monitors.  Own line. */
  ulong doorbell[ FD_SLEEP_BITS_CNT ];
  ulong pad1[ 8 ];

  /* Subset of parked_bits: tiles parked on backpressure, which only a
     consumer's credit return can wake.  Loaded on every credit return. */
  ulong credit_bits[ FD_SLEEP_BITS_CNT ];
  ulong pad2[ 8 ];

  /* Indexed by tile->id; written by the owner and mwaitx only */
  struct __attribute__((aligned(64UL))) {
    ulong word;      /* futex word: 0 parked, 1 running */
    ulong pad0;
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

struct fd_topo;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong fd_sleep_align    ( void );
FD_FN_CONST ulong fd_sleep_footprint( void );

/* fd_sleep_new formats shmem (fd_sleep_align aligned, fd_sleep_footprint
   bytes) as a sleep region with every tile running.  tick_per_ns is
   the fd_tickcount rate used to turn park deadlines into futex
   timeouts.  Returns shmem on success, NULL on failure (logs
   details). */

void * fd_sleep_new( void * shmem,
                     double tick_per_ns );

fd_sleep_t * fd_sleep_join( void * shsleep );

/* fd_sleep_wake_table fills wake (FD_SLEEP_BITS_CNT entries) with the
   (word,mask) pairs covering every tile that polls link_id, and
   returns the pair count (0 if none, or in performance mode).  A
   consumer that never parks never has its bit set, so rings to it are
   free. */

ulong
fd_sleep_wake_table( fd_sleep_wake_t *       wake,
                     struct fd_topo const *  topo,
                     ulong                   link_id );

/* fd_sleep_ring marks tile_id as having work.  Safe from any thread;
   ringing a running tile is harmless. */

static inline void
fd_sleep_ring( fd_sleep_t * sleep,
               ulong        tile_id ) {
  __atomic_fetch_or( &sleep->doorbell[ tile_id>>6 ], 1UL<<(tile_id&63UL), __ATOMIC_RELEASE );
}

/* fd_sleep_wake_check rings the parked consumers of one out link,
   except those parked on backpressure (credit_bits): a frag cannot
   help them, only a credit return can.  One load per pair; the
   second load and the locked OR only on a hit.

   The caller's publish stores (mcache line, seq_mirror) must be
   globally visible before parked_bits is loaded.  x86-TSO allows a
   store to be reordered after a later load (StoreLoad), so without a
   full fence the producer can miss the parked bit while the sleeper's
   re-check (after its locked RMW on parked_bits) misses the frag,
   leaving the frag to the mwaitx sweep or the park cap. */

static inline void
fd_sleep_wake_check( fd_sleep_t *            sleep,
                     fd_sleep_wake_t const * wake,
                     ulong                   wake_cnt ) {
  __atomic_thread_fence( __ATOMIC_SEQ_CST );
  for( ulong k=0UL; k<wake_cnt; k++ ) {
    ulong rung = FD_VOLATILE_CONST( sleep->parked_bits[ wake[ k ].w ] ) & wake[ k ].mask;
    if( FD_UNLIKELY( rung ) ) {
      rung &= ~FD_VOLATILE_CONST( sleep->credit_bits[ wake[ k ].w ] );
      if( FD_LIKELY( rung ) ) __atomic_fetch_or( &sleep->doorbell[ wake[ k ].w ], rung, __ATOMIC_RELEASE );
    }
  }
}

/* Unpark causes, in ParkWake metrics enum order */

#define FD_SLEEP_UNPARK_RING     (0)
#define FD_SLEEP_UNPARK_DEADLINE (1)
#define FD_SLEEP_UNPARK_PENDING  (2)

/* FD_SLEEP_WORD( cause ) is what a wake stores in the word: nonzero
   and distinct per cause */

#define FD_SLEEP_WORD( cause ) (1UL+(ulong)(cause))

/* fd_sleep_park_wait blocks on word until woken or deadline_ticks
   passes (LONG_MAX: no timer, the mwaitx sweep must end the park).
   Returns FD_SLEEP_UNPARK_RING or FD_SLEEP_UNPARK_DEADLINE. */

int
fd_sleep_park_wait( ulong * word,
                    long    deadline_ticks,
                    double  tick_per_ns );

/* fd_sleep_wake_one wakes the tile parked on word for cause. */

void
fd_sleep_wake_one( ulong * word,
                   int     cause );

/* fd_sleep_wake_eventfd is fd_sleep_wake_one for a tile parked in
   fd_sleep_park_wait_epoll. */

void
fd_sleep_wake_eventfd( ulong * word,
                       int     eventfd,
                       int     cause );

/* fd_sleep_park_wait_epoll is fd_sleep_park_wait for a tile with its
   own fds.  Blocks in epoll_pwait on epfd until an fd is ready, a wake,
   or the deadline.  Ready events are returned in evs / *ev_cnt.  epfd
   must hold the tile's eventfd doorbell registered EPOLLIN|EPOLLET
   with data FD_SLEEP_EPOLL_DOORBELL, and the caller must never read
   it: a stale doorbell (word still 0) is waited through, which relies
   on the edge being consumed by the wait. */

struct epoll_event;

int
fd_sleep_park_wait_epoll( int                  epfd,
                          ulong const *        word,
                          struct epoll_event * evs,
                          int                  ev_max,
                          int *                ev_cnt,
                          long                 deadline_ticks,
                          double               tick_per_ns );

/* fd_sleep_eventfd_install creates the eventfd doorbell of every
   sleep_eventfd tile at FD_SLEEP_EVENTFD( tile->id ). */

void
fd_sleep_eventfd_install( struct fd_topo const * topo );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_sleep_fd_sleep_h */
