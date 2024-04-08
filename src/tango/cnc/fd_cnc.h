#ifndef HEADER_fd_src_tango_cnc_fd_cnc_h
#define HEADER_fd_src_tango_cnc_fd_cnc_h

#include "../fd_tango_base.h"

/* A fd_cnc_t provides APIs for out-of-band low bandwidth
   command-and-control ("cnc") signals to a high performance app thread
   ("app").  In the app thread's run loop, as part of its out-of-band
   housekeeping, it uses fd_cnc_t object dedicated to it to send and
   receive information from command and control threads and/or monitoring
   threads.  The basic template for an fd_cnc_t state machine is:

                        app
           new +---------<----------+
            |  |                    |
            |  |        +---<----+  |
        cnc v  v        |  app   |  ^
            |  |        v        ^  |
            |  |  app   |  cnc   |  |
     +--<-- BOOT -->-- RUN -->-- USER -->---+
     | cnc  |  |        |        |  |       |
     |      |  ^        v cnc    |  ^       v
     |      v  | app    |        |  |       |
     |      |  +--<-- HALT       |  +---<---+
     v      |           |        v   app/cnc
     |      +---->----+ |        |
     |          app   | v app    |
     |                v |        |
     |                | |        |
   delete -----<----- FAIL ---<--+
              cnc           app

  That is, when a cnc is created, it is in the BOOT state and the app
  thread that uses it is not running.  When the app thread starts
  running and finishes booting up, it should transition the cnc to the
  RUN state if the thread started up successfully or the FAIL state if
  booting failed (the thread is not running and is considered to be
  unsafe to try restarting).  While in the RUN state:

  - If a cnc thread raises a HALT signal on the app thread's cnc, the
    app thread should cleanup after itself and, just before it stops
    running, transition its cnc to BOOT (FAIL) if the app thread can
    (cannot) be booted again safely.

  - If a cnc thread raises a USER defined signal, the app thread should
    process the signal.  If the app thread resumes running after
    processing the signal, it should transition its cnc to RUN.  If
    this processing results in termination of the app thread, just before
    it stops running, it should transition its cnc to BOOT (FAIL) if the
    app thread can (cannot) be booted again safely.  Note that the cnc
    state alone does not indicate if a USER defined signal was processed
    successfully (e.g. the app thread might chose to ignore a malformed
    command, log the details, and then resume running).  For such
    information, the application can encode additional inputs and
    outputs regarding commands in the cnc app region.  USER defined to
    USER defined transitions (either driven by the app thread as it
    processes a complex signal or by a back-and-forth interaction with
    the cnc thread) are fine and up to the application to define.

  The only thing that can be done to an app thread in the FAIL state is
  postmortem autopsies and clean up.  An app thread should not do a
  RUN->FAIL transition, even if it dies in the RUN state.  If a thread
  dies while in the RUN state, note that the cnc has a heartbeat to help
  cnc threads and/or monitor threads detect such without needing to open
  a cnc command session (specific heartbeating conventions are
  application defined).

  It is often useful to have one USER defined signal to be a no-op
  "ACK".  For this, a cnc thread can signal ACK to the app thread.  If
  the cnc returns to RUN reasonably promptly, the app thread has self
  reported to the cnc thread it is operating correctly.  If it doesn't
  (i.e. times out), the cnc thread can forcibly terminate the app
  thread, move the cnc post termination into the FAIL state and then
  proceed like a normal FAIL.

  A cnc has an application defined type field to help applications
  distinguish between what USER defined signals might be supported by a
  particular app thread. */

/* FD_CNC_{ALIGN,FOOTPRINT} describe the alignment and footprint of a
   fd_cnc_t.  ALIGN is a positive integer power of 2.  FOOTPRINT is a
   multiple of ALIGN.  ALIGN is recommended to be at least double cache
   line to mitigate various kinds of false sharing.  app_sz is assumed
   to be valid (e.g. will not require a footprint larger than
   ULONG_MAX).  These are provided to facilitate compile time
   declarations. */

#define FD_CNC_ALIGN (128UL)
#define FD_CNC_FOOTPRINT( app_sz )                                    \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    FD_CNC_ALIGN,     64UL     ),                                     \
    FD_CNC_APP_ALIGN, (app_sz) ),                                     \
    FD_CNC_ALIGN )

/* FD_CNC_ALIGN describes the alignment and footprint of a fd_cnc_t's
   application region.  This is a power of 2 of the minimal malloc
   alignment (typically 8) and at most FD_CNC_ALIGN. */

#define FD_CNC_APP_ALIGN (64UL)

/* FD_CNC_SIGNAL_* are the standard cnc signals.  All remaining values
   ([4,ULONG_MAX]) are available to implement user defined signals.
   Details of the standard signals are provided above. */

#define FD_CNC_SIGNAL_RUN  (0UL)
#define FD_CNC_SIGNAL_BOOT (1UL)
#define FD_CNC_SIGNAL_FAIL (2UL)
#define FD_CNC_SIGNAL_HALT (3UL)

/* FD_CNC_SUCCESS, FD_CNC_ERR_* are error code return values used by
   cnc APIs.  SUCCESS must be zero, ERR_* are negative and distinct. */

#define FD_CNC_SUCCESS   (0)  /* success */
#define FD_CNC_ERR_UNSUP (-1) /* unsupported on this caller */
#define FD_CNC_ERR_INVAL (-2) /* bad inputs */
#define FD_CNC_ERR_AGAIN (-3) /* potentially transient failure */
#define FD_CNC_ERR_FAIL  (-4) /* permanent failure */

/* fd_cnc_t is an opaque handle of a command-and-control object.
   Details are exposed here to facilitate inlining of many cnc
   operations in performance critical app thread paths. */

#define FD_CNC_MAGIC (0xf17eda2c37c2c000UL) /* firedancer cnc ver 0 */

struct __attribute__((aligned(FD_CNC_ALIGN))) fd_cnc_private {
  ulong magic;     /* ==FD_CNC_MAGIC */
  ulong app_sz;
  ulong type;
  long  heartbeat0;
  long  heartbeat;
  ulong lock;
  ulong signal;
  /* Padding to FD_CNC_APP_ALIGN here */
  /* app_sz bytes here */
  /* Padding to FD_CNC_ALIGN here */
};

typedef struct fd_cnc_private fd_cnc_t;

FD_PROTOTYPES_BEGIN

/* fd_cnc_{align,footprint} return the required alignment and footprint
   of a memory region suitable for use as a cnc.  fd_cnc_align returns
   FD_CNC_ALIGN.  If footprint is larger than ULONG_MAX, footprint will
   silently return 0 (and thus can be used by the caller to validate the
   cnc configuration parameters). */

FD_FN_CONST ulong
fd_cnc_align( void );

FD_FN_CONST ulong
fd_cnc_footprint( ulong app_sz );

/* fd_cnc_new formats an unused memory region for use as a cnc.  Assumes
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  The cnc will be
   initialized to have the given type (should be in [0,UINT_MAX]) with
   an initial heartbeat of now.  The cnc application region will be
   initialized to zero.  Returns shmem (and the memory region it points
   to will be formatted as a cnc, caller is not joined) and NULL on
   failure (logs details).  Reasons for failure include an obviously bad
   shmem region or app_sz. */

void *
fd_cnc_new( void * shmem,
            ulong  app_sz,
            ulong  type,
            long   now );

/* fd_cnc_join joins the caller to the cnc.  shcnc points to the first
   byte of the memory region backing the cnc in the caller's address
   space.  Returns a pointer in the local address space to the cnc on
   success (this should not be assumed to be just a cast of shcnc) or
   NULL on failure (logs details).  Reasons for failure include the
   shcnc is obviously not a local pointer to a memory region holding a
   cnc.  Every successful join should have a matching leave.  The
   lifetime of the join is until the matching leave or caller's thread
   group is terminated. */

fd_cnc_t *
fd_cnc_join( void * shcnc );

/* fd_cnc_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success (this should not be
   assumed to be just a cast of cnc) and NULL on failure (logs details).
   Reasons for failure include cnc is NULL. */

void *
fd_cnc_leave( fd_cnc_t const * cnc );

/* fd_cnc_delete unformats a memory region used as a cnc.  Assumes
   nobody is joined to the region.  Returns a pointer to the underlying
   shared memory region or NULL if used obviously in error (e.g. shcnc
   obviously does not point to a cnc ... logs details).  The ownership
   of the memory region is transferred to the caller on success. */

void *
fd_cnc_delete( void * shcnc );

/* fd_cnc_app_sz returns the size of a the cnc's application region.
   Assumes cnc is a current local join. */

FD_FN_PURE static inline ulong fd_cnc_app_sz( fd_cnc_t const * cnc ) { return cnc->app_sz; }

/* fd_cnc_app_laddr returns local address of the cnc's application
   region.  This will have FD_CNC_APP_ALIGN alignment and room for at
   least fd_cnc_app_sz( cnc ) bytes.  Assumes cnc is a current local
   join.  fd_cnc_app_laddr_const is for const correctness.  The return
   values are valid for the lifetime of the local join. */

FD_FN_CONST static inline void *       fd_cnc_app_laddr      ( fd_cnc_t *       cnc ) { return (void *      )(((ulong)cnc)+64UL); }
FD_FN_CONST static inline void const * fd_cnc_app_laddr_const( fd_cnc_t const * cnc ) { return (void const *)(((ulong)cnc)+64UL); }

/* fd_cnc_type returns the application defined type of a cnc.  Assumes
   cnc is a current local join. */

FD_FN_PURE static inline ulong fd_cnc_type( fd_cnc_t const * cnc ) { return cnc->type; }

/* fd_cnc_heartbeat0 returns the heartbeat assigned when the cnc was
   created.  Assumes cnc is a current local join. */

FD_FN_PURE static inline long fd_cnc_heartbeat0( fd_cnc_t const * cnc ) { return cnc->heartbeat0; }

/* fd_cnc_heartbeat_query returns the value of the cnc's heartbeat
   as of some point in time between when this was called and when this
   returned.  Assumes cnc is a current local join.  This acts as a
   compiler memory fence. */

static inline long
fd_cnc_heartbeat_query( fd_cnc_t const * cnc ) {
  FD_COMPILER_MFENCE();
  long then = FD_VOLATILE_CONST( cnc->heartbeat );
  FD_COMPILER_MFENCE();
  return then;
}

/* fd_cnc_heartbeat is used by an app thread to update the cnc's
   heartbeat.  Heartbeat values are application defined but typical
   usage is something that monotonically increases (e.g. the host
   wallclock, host tickcounter or just a flat counter).  It is
   recommended app threads do cnc heartbeats with intervals that are
   uniform random distributed in a range like [min,2*min] nanoseconds
   for some reasonably fast to a human but slow to the computer value
   of min.  This keeps load from heartbeating low, keeps the system
   human real time responsive, prevents heartbeats from multiple cnc
   auto-synchronizing and gives a strict range in time over which a cnc
   thread should expect to see a heartbeat from a normally running app
   thread.  Assumes cnc is a current local join.  This acts as a
   compiler memory fence. */

static inline void
fd_cnc_heartbeat( fd_cnc_t * cnc,
                  long       now ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc->heartbeat ) = now;
  FD_COMPILER_MFENCE();
}

/* fd_cnc_signal query observes the current signal posted to the cnc.
   Assumes cnc is a current local join.  This is a compiler fence.
   Returns the current signal on the cnc at some point in time between
   when this was called and this returned. */

static inline ulong
fd_cnc_signal_query( fd_cnc_t const * cnc ) {
  FD_COMPILER_MFENCE();
  ulong s = FD_VOLATILE_CONST( cnc->signal );
  FD_COMPILER_MFENCE();
  return s;
}

/* fd_cnc_signal atomically transitions the cnc to signal s.  Assumes
   cnc is a current local join and the caller is currently allowed to do
   a transition to s.  Specifically:

     CNC thread with open command session:

     - RUN->HALT: signal an app thread to shutdown

     - RUN->USER defined: as per application requirements

     - USER defined->USER defined: as per application requirements

     Running APP thread:

     - BOOT->RUN: when app thread it is done booting ... should be just
       before app thread enters its run loop.

     - BOOT->FAIL: if app thread failed to boot ... should be just
       before app thread stops running.

     - HALT->BOOT: when app thread is done halting ... should be just
       before app thread stops running.

     - USER defined->RUN: when app thread is done processing signal and
       can resume running ... should be just before app thread resumes
       its run loop.

     - USER defined->BOOT: when CNC thread signal processing halted the
       app thread normally ... should be just before app thread stops
       running.

     - USER defined->FAIL: when CNC thread signal processing halted the
       app thread abnormally ... should be just before app thread stops
       running.

     - USER defined->USER defined: as per application requirements

   See above state machine for more details.  This function is a
   compiler memory fence (e.g. caller can populate the cnc app region
   with app signal specific details and all the memory operations to the
   app region will be issued before s is signaled). */

static inline void
fd_cnc_signal( fd_cnc_t * cnc,
               ulong      s ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc->signal ) = s;
  FD_COMPILER_MFENCE();
}

/* fd_cnc_open opens a new command session to an app thread.  Returns 0
   (FD_CNC_SUCCESS) on success and a negative (FD_CNC_ERR_*) on failure
   (logs details).  On successful return, caller will have an open
   command session on the cnc and the cnc will be in the RUN state.  On
   failure, caller does not have a command session on cnc.

   Reasons for FD_CNC_ERR_UNSUP include not running on a hosted target,
   not running on an atomic capable target and strange thread group id;
   this is a permanent failure.  Reasons for FD_CNC_ERR_INVAL include
   NULL cur; this is a permanent failure.  Reasons for FD_CNC_ERR_FAIL
   include app thread is not running and cannot be restarted cleanly;
   this is a permanent failure.  Reasons for FD_CNC_ERR_AGAIN include
   app thread is bootable, is in the process of booting or is in the
   process of halting (and thus might be running later) or there is
   already an open command session on app thread; this failure is
   _potentially_ transient.

   Caller should not leave the join while it has an open command
   session.  Caller should not close an open command session while it
   has a signal pending on it.  If the caller dies with an open command
   session, the next cnc thread will try to implicitly close it to
   recover (logging details as necessary). */

int
fd_cnc_open( fd_cnc_t * cnc );

/* fd_cnc_wait waits up to dt ns for the cnc to transition to something
   other than test.  Returns the last observed cnc signal (which can be
   used detect result of the way).  dt==LONG_MAX will do a blocking
   wait.  dt<=0 will poll cnc once.  If _opt_now is non-NULL, *_opt_now
   will contain the wallclock observed just before the last time the cnc
   was queried on return.  The wait is OS friendly (e.g. will not block
   other threads that might be running on the same core as the cnc
   thread as such threads are often scheduled to shared a common
   administrative core). */

ulong
fd_cnc_wait( fd_cnc_t const * cnc,
             ulong            test,
             long             dt,
             long *           _opt_now );

/* fd_cnc_close ends the current command session on cnc.  Assumes caller
   has an open command session on cnc and there are no signals being
   processed by the app thread (e.g. the sync is in the RUN, BOOT or
   FAIL state).  This function is a compiler fence. */

static inline void
fd_cnc_close( fd_cnc_t * cnc ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc->lock ) = 0UL;
  FD_COMPILER_MFENCE();
}

/* fd_cnc_strerror converts a FD_CNC_SUCCESS / FD_CNC_ERR_* code into
   a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_cnc_strerror( int err );

/* fd_cstr_to_cnc_signal converts the cstr pointed to by into a cnc
   signal value.  Return value undefined if cstr does not point to a cnc
   signal cstr. */

FD_FN_PURE ulong
fd_cstr_to_cnc_signal( char const * cstr );

/* fd_cnc_signal_cstr pretty prints the cnc signal value into buf.  buf
   must point to a character buffer with at least
   FD_CNC_SIGNAL_CSTR_BUF_MAX bytes.  Always returns buf.  If buf is
   non-NULL, the buffer pointed at will be populated with a proper '\0'
   terminated cstr on return (and one that fd_cstr_to_cnc_signal
   properly convert back to signal). */

#define FD_CNC_SIGNAL_CSTR_BUF_MAX (21UL)

char *
fd_cnc_signal_cstr( ulong  signal,
                    char * buf );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_cnc_fd_cnc_h */

