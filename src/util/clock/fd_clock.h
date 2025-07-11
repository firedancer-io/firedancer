#ifndef HEADER_fd_src_util_clock_fd_clock_h
#define HEADER_fd_src_util_clock_fd_clock_h

#include "../log/fd_log.h"

/* fd_clock provides a persistent interprocess shared memory object for
   synchronizing a pair of clocks and using that the synchronization
   lockfree between an arbitrary number of observer threads and a
   calibrating thread.

   Common usage is to have 1 adminstrative thread in an application
   synchronize the cheap low quality CPU invariant tickcounter, NIC
   tickcounters, FPGA tickcounters, GPU tickcounters, etc to the system
   clock so that all threads in that application can ultra cheaply
   convert fast-but-inaccurate tickcounter reads across a wide variety
   of devices into a wallclock time that can be compared enterprise
   wide.

   This is typically several times cheaper than the reading system clock
   with comparable accuracy, less jitter, and more flexibility
   (especially when using heterogeneous hardware).

   Note that any thread can do the calibration.  The only concurrency
   restriction is that different threads should not attempt to calibrate
   a fd_clock at the same time.  Among other things, this means that
   single threaded modes of operation are supported.

   Summary usage:

     ... create a fd_clock for the clock pair (clock_x/args_x,clock_y/args_y)

       ... typically clock_x/args_x is the fast-but-inaccurate local clock
       ... (e.g. the CPU invariant tickcounter) and clock_y/args_y is the
       ... slow-but-accurate reference global clock (e.g. clock_gettime /
       ... CLOCK_REALTIME)

       ... user parameters

       long   recal_avg  = (long)10e6; ... target clock epoch duration, in y-ticks, no default (10e6 <> 10 ms if y-ticks are ns)
       long   recal_jit  = 0L;         ... target clock epoch jitter,   in y-ticks, 0 -> use default (~recal_avg/128)
       double recal_hist = 0.;         ... ~number of recent clock epochs to use for clock rate estimation, 0 -> use a default (3)
       double recal_frac = 0.;         ... ~target max clock drift fraction to correct in a clock epoch,    0 -> use a default (1)

       FD_LOG_NOTICE(( "starting initial calibration" ));

       ... the user can use whatever method is best to joint read the
       ... x-clock and y-clock.  fd_clock_join_read provides a generic
       ... method to approximate joint reading an arbitrary clock pair.

       long init_x0;
       long init_y0;
       int  err = fd_clock_joint_read( clock_x, args_x, clock_y, args_y, &init_x0, &init_y0, NULL );
       if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_clock_joint_read failed (%i-%s)", err, fd_clock_strerror( err ) ));

       ... wait / do other stuff for O(1) epochs

       FD_LOG_NOTICE(( "finishing initial calibration" ));

       long init_x1;
       long init_y1;
       err = fd_clock_joint_read( clock_x, args_x, clock_y, args_y, &init_x1, &init_y1, NULL );
       if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_clock_joint_read failed (%i-%s)", err, fd_clock_strerror( err ) ));

       long init_dx = init_x1 - init_x0;
       long init_dy = init_y1 - init_y0;
       if( FD_UNLIKELY( !((init_dx>0L) & (init_dy>0L)) ) ) FD_LOG_ERR(( "initial calibration failed" ));

       double init_w = (double)init_dx / (double)init_dy;

       void * shmem   = ... alloc fd_clock_align() / fd_clock_footprint() compat shared memory;
       void * shclock = fd_clock_new( shmem, recal_avg, recal_jit, recal_hist, recal_frac, init_x1, init_y1, init_w );
       if( FD_UNLIKELY( !shclock ) ) FD_LOG_ERR(( "fd_clock_new failed" ));

       ... at this point, shclock==shmem and is ready for to joined by
       ... observing threads and the calibrating thread

     ... join a fd_clock (clock_x/args_x are how to read the x-clock on the caller)

       void       * lmem    = ... alloc fd_clock_t compat local memory;
       void       * shclock = ... map fd_clock into the caller's local address space with the proper alignment and footprint;
       fd_clock_t * clock   = fd_clock_join( lmem, shclock, clock_x, args_x );
       if( FD_UNLIKELY( !clock ) ) FD_LOG_ERR(( "fd_clock_new failed" ));

       ... at this point, clock==lmem is a current local join

     ... leave a fd_clock (clock is a current local join)

       void * lmem = fd_clock_leave( clock ); // returns lmem on success, NULL on error (logs details)

       ... at this point, clock is no longer a join and lmem can freed /
       ... reused

     ... destroy a fd_clock (nobody should be joined at this point)

       void * shclock = ... map clock into the caller's local address space with the proper alignment and footprint;
       void * shmem   = fd_clock_delete( shclock ); returns shclock on success, NULL on error (logs details)

       ... at this point, shmem no longer holds the state of a fd_clock
       ... and can be freed / reused

     ... observe a fd_clock (clock is a current local join)

       ... this can be done by any thread at any time (non-blocking
       ... lockfree).

       long now = fd_clock_now( clock );

       ... now is an accurate estimate of the time on the y-clock based
       ... on a local read of the x-clock

     ... recalibrate a fd_clock (clock is a current local join to a fd_clock)

       ... this should be done by a single thread on roughly the
       ... recommended schedule (e.g. an admin tile that does low
       ... priority application wide chores)

       ... tile setup

       ...
       long recal_next = fd_clock_recal_next( clock ); ... get the current recommended next recal
       ...

       ... tile run loop

       for(;;) {
         ...
         long now = fd_clock_now( clock );
         ...
         if( FD_UNLIKELY( now>=recal_next ) ) {

           ... as per the above, user can use other methods for joint
           ... reading the x-clock and y-clock if applicable

           long x1;
           long y1;
           int  err = fd_clock_joint_read( clock_x, args_x, clock_y, args_y, &x1, &y1, NULL );
           if( FD_UNLIKELY( err ) )
             FD_LOG_WARNING(( "fd_clock_joint_read failed (%i-%s); attempting to continue", err, fd_clock_strerror( err ) ));
           else
             recal_next = fd_clock_recal( clock, x1, y1 );
         }
         ...
       }

     ... HPC tile usage (advanced API)

       ... tile setup ...

       ...
       fd_clock_shmem_t const * shclock = fd_clock_shclock_const( clock );
       fd_clock_epoch_t epoch[1];
       fd_clock_epoch_init( epoch, shclock );
       ...

       ... tile run loop

       for(;;) {

         if( ... time for tile housekeeping ... ) { ... should be done much more often than recal_avg
           ...
           fd_clock_epoch_refresh( epoch, shclock );
           ...
         }

         ... critical path usage ...

         ...
         long x   = ... an x-clock observation, e.g. clock_x( args_x ), hardware tickcount, etc;
         ...
         long now = fd_clock_y( epoch, x ); ... O(1) ns
         ...

       }
*/

/* FD_CLOCK_SUCCESS (0) is used by fd_clock APIs to indicate an
   operation succeeded.  FD_CLOCK_ERR_* (negative integers) are used by
   these APIs to indicate an operation failed and why. */

#define FD_CLOCK_SUCCESS ( 0) /* Success */
#define FD_CLOCK_ERR_X   (-1) /* Failed because the x-clock is not well behaved (e.g. didn't tick forward) */
#define FD_CLOCK_ERR_Y   (-2) /* Failed because the y-clock is not well behaved (e.g. didn't tick forward) */

/* FD_CLOCK_ALIGN / FD_CLOCK_FOOTPRINT allow for compile-time
   declarations of clock shared memory region. */

#define FD_CLOCK_ALIGN     (128UL)
#define FD_CLOCK_FOOTPRINT (640UL)

/* An ideal fd_clock_func_t is a function such that:

     long dx = clock( args );
     ... stuff ...
     dx = clock( args ) - dx;

   yields a strictly positive dx where dx approximates the amount of
   wallclock time elapsed in some clock specific unit (e.g. nanoseconds,
   CPU ticks, etc) for a reasonable amount of "stuff" (including no
   "stuff").  args allows arbitrary clock specific context to be passed
   to the clock function.  Many of the below APIs make best efforts to
   handle common clock dysfunctions (like getting stepping backwards due
   to operators / NTP manipulating the underlying clock hardware
   out-of-band).  (Applications that need a non-const args can cast away
   the const or cast the function pointer as necessary.) */

typedef long (*fd_clock_func_t)( void const * args );

/* A fd_clock_shmem_t is a quasi-opaque handle that to a shared memory
   region used to hold the state of a fd_clock.  A fd_clock_t is a
   quasi-opaque handle to a join to a fd_clock. */

struct fd_clock_shmem_private;
typedef struct fd_clock_shmem_private fd_clock_shmem_t;

struct fd_clock_private;
typedef struct fd_clock_private fd_clock_t;

/* A fd_clock_epoch_t gives a linear approximation to the relationship
   between two clocks over a clock epoch for use by the advanced APIs. */

struct __attribute__((aligned(128))) fd_clock_epoch { /* double cache line alignment to avoid false sharing */

  /* seq0 is the epoch's sequence number. */

  ulong seq0;

  /* x0 is the raw value observed on the x-clock at the epoch start.  In
     x-ticks (e.g. ticks if x is a CPU invariant tickcounter). */

  long x0;

  /* y0 is the raw value for the y-clock at the epoch start.  In
     y-ticks (e.g. ns if y is the system wallclock in ns). */

  long y0;

  /* w is the estimate of the recent x-tick per y-tick rate at epoch
     start (e.g. in GHz = tick/ns if x is a CPU invariant tickcounter
     and y is the system wallclock in ns). */

  double w;

  /* y0_eff is the effective value for the y-clock at the epoch start.
     This may be different from the raw value in order to preserve
     monotonicity of y-clock estimates across epochs.  In y-ticks (e.g.
     ns if y is the system wallclock in ns). */

  long y0_eff;

  /* m is the y-tick per x-tick rate used to estimate the value that
     would have been observed on the y-clock given an observation on the
     x-clock (e.g. in ns/tick if x is a CPU invariant tickcounter and y
     is the system wallclock in ns).  This may be different from 1/w
     because the clock might be absorbing the clock drift observed at
     the end of the previous epoch. */

  double m;

  /* seq1==seq0 when parameters are valid.  To update epoch parameters,
     first, seq1 is updated (marking the parameters as invalid).  Then
     the above parameters are updated.  Last, seq0 is updated (marking
     parameters as valid again).  Since sequence number wrapping is not
     an issue practically (would take eons), observers read this
     structure sequentially forward (seq0->params->seq1) and then
     validate seq0==seq1 to do a non-blocking lockfree read.  Assumes
     the usual write visibility ordering properties common on x86. */

  ulong seq1;

};

typedef struct fd_clock_epoch fd_clock_epoch_t;

/* fd_clock private API **********************************************/

/* This is exposed here to facilitate inlining of various clock
   operations for use in high performance contexts. */

/* FD_CLOCK_JOINT_READ_CNT gives the number of iterations used by
   fd_clock_joint_read.  Larger values cost linearly more but can
   improve joint read accuracy approximately hyperbolically in an
   statistical extremal value sense (assuming clock read timing is a
   shifted exponentially distributed).  Must be at least 1. */

#define FD_CLOCK_JOINT_READ_CNT (3UL)

/* Internals of a fd_clock_shmem_t */

/* FD_CLOCK_EPOCH_CNT gives the number of epochs parameters to cache.
   Must be a positive integer power of 2.  Larger than 1 is strongly
   recommended to reduce collision risks between observer threads and
   the calibrating thread. */

#define FD_CLOCK_EPOCH_CNT (4UL)

/* FD_CLOCK_MAGIC specifies the fd_clock shared memory region layout. */

#define FD_CLOCK_MAGIC (0xfdc101c3a61c0000UL) /* fd clock magic ver 0 */

struct __attribute__((aligned(128))) fd_clock_shmem_private {

  /* First cache line pair */

  ulong magic; /* == FD_CLOCK_MAGIC */

  /* clock epochs have sequence numbers.  seq is the most recent
     epoch sequence number published by the calibrating thread.  That
     is, epochs [0,seq] are guaranteed to have been published, seq+1 is
     either not published or in the process of getting published.
     [seq+2,inf) have definitely not been published. */
  /* FIXME: consider using a versioned lock here to make recalibration
     explicit? */

  ulong seq;

  /* recal_next gives the recommended time on the y-clock when to
     recalibrate next, in y-ticks. */

  long recal_next;

  /* err_cnt gives the number of times that recalibration potentially
     broke monotonicity of y-clock estimates due to operators jerking
     around the x-clock and/or y-clock out-of-band. */

  ulong err_cnt;

  /* parameters derived from the user configuration */

  double recal_alpha; /* == 1. / (1. + recal_hist) */
  double recal_beta;  /* == recal_frac / ( recal_avg + pow2_dn(recal_jit) ) */
  long   recal_min;   /* == recal_avg - pow2_dn(recal_jit) */
  ulong  recal_mask;  /* == 2*pow2_dn(recal_jit)-1 */

  /* recal_avg is the recommended average interval between
     recalibrations in y-ticks.  Shorter values increase overhead,
     increase cache traffic between the calibrating thread and observer
     threads and eventually degrade accuracy due to quantization errors
     and synchronization errors in x-clock / y-clock joint reads that
     get relatively worse as the interval intervals.  Longer values
     decrease overheads and reduce cache traffic but also eventually
     degrade accuracy due to various long timescale sources of clock
     drift / non-linearites (e.g. thermal changes).

     In short, when synchronizing two clocks, there is an optimal value
     in the middle for recal avg that gets the best overall tradeoff
     between sync accuracy and sync overhead.  For typical real world
     use cases (e.g. the CPU invariant tickcount and the system
     wallclock), recal_avg should be O(10s) milliseconds for ns-scale
     accuracy.

     Similarly, recal_jit is the recommended jitter between
     recalibrations in y-ticks.  This is a positive value much less than
     recal_avg.  In short, it is really bad idea to do anything in
     distributed systems on completely regular intervals because as such
     can become a source of all sorts of subtle and not-so-subtle
     anomalies.  Values of 1/128 of recal_avg are reasonable for most
     apps.

     recal_hist gives roughly how many recent epochs to use for
     estimating the recent clock rate.  Smaller values allow for more
     adaptivity when syncing low quality clocks.  Larger values allow
     higher accuracy when syncing in high quality clocks.  Positive, 3
     is a reasonable value for most apps.

     recal_frac gives what fraction of clock drift observed at the end
     of an epoch should try to be absorbed over the next epoch.  Values
     not in (0,2) are likely unstable.  Values near 1 are recommended.
     1 is a reasonable value for most apps. */

  long   recal_avg;  /* positive */
  long   recal_jit;  /* in [1,recal_avg] */
  double recal_hist; /* non-negative */
  double recal_frac; /* in ~(0,2) */

  /* init_x1 and init_y1 are the x-clock and y-clock joint read
     observations used for epoch 0 when the clock was created.  init_w
     is the initial estimate for the x-ticks per y-ticks rate. */

  long   init_x0;
  long   init_y0;
  double init_w;  /* positive */

  /* FD_CLOCK_EPOCH_CNT cache line pairs */

  /* epoch is a direct mapped cache of recently published epochs.  If
     epoch seq is in the epoch cache, it will be at:

       idx = seq & (FD_CLOCK_EPOCH_CNT-1)

     Each epoch is on their own cache line pair to minimize false
     sharing between the calibrating thread and observer threads. */

  fd_clock_epoch_t epoch[ FD_CLOCK_EPOCH_CNT ];

};

/* Internals of a fd_clock_t */

struct fd_clock_private {
  fd_clock_shmem_t * shclock; /* Location of the clock shared memory in the local join's address space */
  fd_clock_func_t    clock_x; /* How to read the x-clock for this local join */
  void const       * args_x;  /* " */
};

/* End of private API *************************************************/

FD_PROTOTYPES_BEGIN

/* Constructors / destructors *****************************************/

/* fd_clock_{align,footprint,new,join,leave,delete} provide the usual
   persistent interprocess constructors/deconstructors. */

ulong fd_clock_align    ( void ); /* ==FD_CLOCK_ALIGN     */
ulong fd_clock_footprint( void ); /* ==FD_CLOCK_FOOTPRINT */

void *
fd_clock_new( void * shmem,
              long   recal_avg,
              long   recal_jit,
              double recal_hist,
              double recal_frac,
              long   init_x0,
              long   init_y0,
              double init_w );

fd_clock_t *
fd_clock_join( void *          lmem,
               void *          shclock,
               fd_clock_func_t clock_x,
               void const *    args_x );

void * fd_clock_leave ( fd_clock_t * clock   ); /* returns lmem */
void * fd_clock_delete( void *       shclock ); /* returns shmem */

/* Accessors **********************************************************/

static inline long   fd_clock_recal_avg ( fd_clock_t const * clock ) { return clock->shclock->recal_avg;  }
static inline long   fd_clock_recal_jit ( fd_clock_t const * clock ) { return clock->shclock->recal_jit;  }
static inline double fd_clock_recal_hist( fd_clock_t const * clock ) { return clock->shclock->recal_hist; }
static inline double fd_clock_recal_frac( fd_clock_t const * clock ) { return clock->shclock->recal_frac; }
static inline long   fd_clock_init_x0   ( fd_clock_t const * clock ) { return clock->shclock->init_x0;    }
static inline long   fd_clock_init_y0   ( fd_clock_t const * clock ) { return clock->shclock->init_y0;    }
static inline double fd_clock_init_w    ( fd_clock_t const * clock ) { return clock->shclock->init_w;     }

static inline void const *    fd_clock_shclock_const( fd_clock_t const * clock ) { return clock->shclock; }
static inline fd_clock_func_t fd_clock_clock_x      ( fd_clock_t const * clock ) { return clock->clock_x; }
static inline void const *    fd_clock_args_x       ( fd_clock_t const * clock ) { return clock->args_x;  }

static inline void * fd_clock_shclock( fd_clock_t * clock ) { return clock->shclock; }

/* Basic observer API *************************************************/

/* fd_clock_now returns an estimate of the y-clock (which is typically
   the slow-but-accurate global reference clock with the desired units
   ... e.g. the system wallclock in ns) by making a local observation of
   the x-clock (which is typically is fast-but-inaccurate local
   tickcounter not in the desired units ... e.g. the CPU invariant
   tickcounter in CPU ticks).  Assumes the clock has been recently
   calibrated.  Does no input argument checking.  For common clock-x /
   clock-y pairs, usually several fold faster, more deterministic and
   comparable accuracy to reading the y-clock.  The return value should
   be interpreted as just before when the call returned (as opposed to,
   say, just after when the call was entered).

   This is a composite of several of the advanced observer API calls.
   As such, that can accelerated further by deconstructing the call into
   lazily loading clock epoch parameters in tile housekeeping and using
   the lazily loaded epoch directly in the tile run loop.  Typically
   gets O(1) ns overhead with optimal cache and NUMA behavior between
   the calibrating thread and all the concurrent observer threads. */

long
fd_clock_now( void const * clock ); /* fd_clock_func_t compat */

/* Basic calibrator API ***********************************************/

/* fd_clock_{recal_next,err_cnt} returns the {time on the y-clock when
   it is recommended to recalibrate the clock next,number of errors
   detected with the underlying clock sources}. */

static inline long  fd_clock_recal_next( fd_clock_t const * clock ) { return clock->shclock->recal_next; }
static inline ulong fd_clock_err_cnt   ( fd_clock_t const * clock ) { return clock->shclock->err_cnt;    }

/* fd_clock_reset_err_cnt resets the error counter */

static inline void fd_clock_reset_err_cnt( fd_clock_t * clock ) { clock->shclock->err_cnt = 0L; }

/* fd_clock_joint_read reads the time on two different arbitrary clocks,
   an x-clock (specified by clock_x / args_x) and a y-clock (specified
   by clock_y / args_y), "simultaneously".  The x-clock and y-clock do
   not have to use the same units.  Returns SUCCESS (0) on success.  On
   return, if opt_x / opt_y is non-NULL, *opt_x / *opt_y will contain
   the time observed on the x-clock / y-clock in x-ticks / y-ticks.  If
   opt_dx is non-NULL, *opt_dx will contain the read accuracy in
   x-ticks.  Specifically, the y-clock was observed at some time on the
   x-clock in the interval [x-dx,x+dx].  Does no input argument
   checking.

   Returns a negative integer error code on failure.  On return, *opt_x
   / *opt_y / *opt_dx are unchanged.  Reasons for failure include ERR_X
   / ERR_Y (the x-clock / y-clock showed a negative clock interval
   between adjacent calls ... i.e the clocks passed to joint_read aren't
   in fact well-behaved clocks).

   In typical usage, x-clock is the fast-but-inaccurate local clock
   (e.g. the CPU invariant tickcounter) and y-clock is the
   slow-but-accurate reference global clock (e.g. the system wallclock).

   This API is not required.  If the calibrating thread has a better
   method (e.g. lower cost / lower jitter) for reading the two clocks
   "simultaneously", they can use that with the recal/step APIs below. */

int
fd_clock_joint_read( fd_clock_func_t clock_x, void const * args_x,
                     fd_clock_func_t clock_y, void const * args_y,
                     long * opt_x, long * opt_y, long * opt_dx );

/* fd_clock_recal and fd_clock_step end the current epoch for clock
   and start a new epoch.  The new epoch will start at the time x1 on
   the x-clock and y1 gives the time observed on the y-clock at x1.
   Ideally, x1 and y1 have been recently jointly read (e.g. read via
   fd_clock_joint_read immediately before calling this or by any other
   suitable method for the specific clock pair).  Returns the
   recommended time on the y-clock when to recalibrate next.

   For fd_clock_recal, the step will be such that monotonicity of
   y-clock estimates will be strictly preserved if the underlying clocks
   are proper clocks.  If this detects the underlying clocks are not
   well-behaved (e.g. getting stepped backward out-of-band), this will
   make a best effort to handle such and record the potential
   monotonicity failure.

   For fd_clock_step, the clock will be stepped to x1,y1 with a x-tick
   per y-tick rate of w1 without regard for whether or not that
   preserves monotonicity with the most recent epoch.  This can be used
   to recover a dormant clock after a long period of no calibration or
   to handle situations where the calibrating thread explicity nows the
   the x-clock and/or y-clock were stepped out-of-band (e.g.  the
   superuser manually changing the time on the system wallclock). */

long fd_clock_recal( fd_clock_t * clock, long x1, long y1 );
long fd_clock_step ( fd_clock_t * clock, long x1, long y1, double w1 );

/* Advanced observer API **********************************************/

/* fd_clock_seq returns the most recently published epoch sequence
   number observed at some point during the call.  This is a compiler
   memory fence.  Does no input argument checking. */

static inline ulong
fd_clock_seq( fd_clock_shmem_t const * shclock ) {
  FD_COMPILER_MFENCE();
  ulong seq = shclock->seq;
  FD_COMPILER_MFENCE();
  return seq;
}

/* fd_clock_epoch_read attempts to read the synchronization parameters
   for clock epoch seq from the clock's epoch cache.  clock is a valid
   local join to a fd_clock.  Returns epoch and *epoch was always
   written.

   On return, if epoch->seq0!=epoch->seq1, the caller collided with an
   in-progress recalibration on the calibrating thread while attempting
   to read seq ... as the caller has probably fallen behind (or somehow
   ended up ahead of the calibrating thread), the caller should update
   seq to the most recent published sequence number and try again.

   Otherwise (epoch->seq0==epoch->seq1), *epoch contains the parameters
   for epoch->seq0.  If delta=seq-epoch->seq0 is positive / negative,
   the caller is ahead / behind of the calibrating thread (and the
   magnitude gives a rough estimate of how far).  If delta==0, the
   desired parameters are in *epoch.

   This is a compiler memory fence.  Does no input argument checking.

   TL;DR If seq==epoch->seq0==epoch->seq1, the call was successful.  If
   not, the caller should update seq and try again. */

static inline fd_clock_epoch_t *
fd_clock_epoch_read( fd_clock_shmem_t const * shclock,
                     ulong                    seq,
                     fd_clock_epoch_t *       epoch ) {

  fd_clock_epoch_t const * e = shclock->epoch + (seq & (FD_CLOCK_EPOCH_CNT-1UL));

  FD_COMPILER_MFENCE();
  ulong  seq0   = e->seq0;
  FD_COMPILER_MFENCE();
  long   x0     = e->x0;
  long   y0     = e->y0;
  double w      = e->w;
  long   y0_eff = e->y0_eff;
  double m      = e->m;
  FD_COMPILER_MFENCE();
  ulong  seq1   = e->seq1;
  FD_COMPILER_MFENCE();

  epoch->seq0   = seq0;
  epoch->x0     = x0;
  epoch->y0     = y0;
  epoch->w      = w;
  epoch->y0_eff = y0_eff;
  epoch->m      = m;
  epoch->seq1   = seq1;

  return epoch;
}

/* fd_clock_epoch_init populates epoch with parameters for fd_clock's
   current epoch as observed at some point during the call.  Does no
   input argument checking.  Returns epoch. */

static inline fd_clock_epoch_t *
fd_clock_epoch_init( fd_clock_epoch_t       * epoch,
                     fd_clock_shmem_t const * shclock ) {
  for(;;) {
    ulong seq = fd_clock_seq( shclock );
    fd_clock_epoch_read( shclock, seq, epoch );
    if( FD_LIKELY( (epoch->seq0==seq) & (epoch->seq1==seq) ) ) break;
    FD_SPIN_PAUSE();
  }
  return epoch;
}

/* fd_clock_epoch_refresh refreshes epoch with parameters of the current
   epoch as observed at some point in time during the call assuming that
   epoch contains previous published epoch parameters.  Does no input
   argument checking.  Returns epoch. */

static inline fd_clock_epoch_t *
fd_clock_epoch_refresh( fd_clock_epoch_t       * epoch,
                        fd_clock_shmem_t const * shclock ) {
  if( FD_UNLIKELY( epoch->seq0!=fd_clock_seq( shclock ) ) ) fd_clock_epoch_init( epoch, shclock );
  return epoch;
}

/* fd_clock_{x0,y0,w,y0_eff,m} returns the {raw x-clock epoch start
   time, raw y-clock epoch start time, estimated recent average x-tick
   per y-tick rate at epoch start,effective epoch y-clock start time,
   y-tick per x-tick conversion In effect for this epoch}.
   Specifically, this epoch estimates the y-clock from the x-clock
   observation x_obs via:

     y_est = y0_eff + round( m*(x_obs-x0) ) */

static inline long   fd_clock_x0    ( fd_clock_epoch_t const * epoch ) { return epoch->x0;     }
static inline long   fd_clock_y0    ( fd_clock_epoch_t const * epoch ) { return epoch->y0;     }
static inline double fd_clock_w     ( fd_clock_epoch_t const * epoch ) { return epoch->w;      }
static inline long   fd_clock_y0_eff( fd_clock_epoch_t const * epoch ) { return epoch->y0_eff; }
static inline double fd_clock_m     ( fd_clock_epoch_t const * epoch ) { return epoch->m;      }

/* fd_clock_y returns an estimate of what would have been observed on
   the y-clock given the observation x from the x-clock and the clock
   synchronization parameters in epoch.  Does no input argument
   checking.  Ideally x should have been observed during the epoch but
   reads from just before or just after the epoch are typically usable
   too. */

static inline long
fd_clock_y( fd_clock_epoch_t const * epoch,
            long                     x ) {
  return epoch->y0_eff + (long)(0.5 + epoch->m*(double)(x-epoch->x0));
}

/* Misc APIs **********************************************************/

/* fd_clock_strerror converts a FD_CLOCK_SUCCESS / FD_CLOCK_ERR code
   into a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

char const * fd_clock_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_clock_fd_clock_h */
