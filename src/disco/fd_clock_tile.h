#ifndef HEADER_fd_src_disco_fd_clock_tile_h
#define HEADER_fd_src_disco_fd_clock_tile_h

/* fd_clock_tile.h provides fd_clock convenience APIs for tiles */

#include "../tango/tempo/fd_tempo.h"
#include "../util/clock/fd_clock.h"

/* fd_clock_tile_t is a fast nanosecond clock source for Firedancer
   tiles (single-threaded usage). */

struct fd_clock_tile {
  fd_clock_shmem_t shmem[1];
  fd_clock_t       clock[1];
  fd_clock_epoch_t epoch[1];
};

typedef struct fd_clock_tile fd_clock_tile_t;

FD_PROTOTYPES_BEGIN

/* fd_clock_tile_init creates a new fd_clock_tile_t.  Assumes that the
   calling thread has pre-calibrated fd_tempo tick_per_ns value. */

static inline void
fd_clock_tile_init( fd_clock_tile_t * clock ) {
  /* fdctl calibrates tick_per_ns on startup, no need to calibrate here */
  double init_w = (double)fd_tempo_tick_per_ns( NULL );

  long init_x0, init_y0;
  int  clock_err = fd_clock_joint_read( _fd_tickcount, NULL, fd_log_wallclock_host, NULL, &init_x0, &init_y0, NULL );
  if( FD_UNLIKELY( clock_err ) ) FD_LOG_ERR(( "fd_clock_joint_read failed (%i-%s)", clock_err, fd_clock_strerror( clock_err ) ));

  long   recal_avg  = 10e6L; /* 10ms */
  void * shclock = fd_clock_new( clock->shmem, recal_avg, 0L, 0., 0., init_x0, init_y0, init_w );
  if( FD_UNLIKELY( !shclock ) ) FD_LOG_ERR(( "fd_clock_new failed" ));

  fd_clock_t * clock_ptr = fd_clock_join( clock->clock, shclock, _fd_tickcount, NULL );
  if( FD_UNLIKELY( !clock_ptr ) ) FD_LOG_ERR(( "fd_clock_join failed" ));

  fd_clock_epoch_init( clock->epoch, clock->shmem );
}

/* fd_clock_tile_recal_next returns the wallclock deadline after which
   the next recal should be done. */

static inline long
fd_clock_tile_recal_next( fd_clock_tile_t const * clock ) {
  return fd_clock_recal_next( clock->clock );
}

/* fd_clock_tile_recal is called periodically to synchronize tickcount
   to log_wallclock.  Returns the wallclock deadline after which the
   next recal should be done. */

static inline long
fd_clock_tile_recal( fd_clock_tile_t * clock ) {
  long x; long y;
  int err = fd_clock_joint_read( _fd_tickcount, NULL, fd_log_wallclock_host, NULL, &x, &y, NULL );
  if( FD_UNLIKELY( err ) ) {
    /* on recal fail, retry in 1ms */
    FD_LOG_WARNING(( "fd_clock_joint_read failed (%i-%s)", err, fd_clock_strerror( err ) ));
    return ( clock->shmem->recal_next = fd_clock_epoch_y( clock->epoch, fd_tickcount() ) + 1000000L );
  }
  long recal_next = fd_clock_recal( clock->clock, x, y );
  fd_clock_epoch_refresh( clock->epoch, clock->shmem );
  return recal_next;
}

/* fd_clock_tile_now returns an approximation of fd_log_wallclock. */

static inline long
fd_clock_tile_now( fd_clock_tile_t const * clock ) {
  return fd_clock_epoch_y( clock->epoch, fd_tickcount() );
}

/* fd_clock_tile_recal_due returns 1 if a recalibration is due, else 0. */

static inline int
fd_clock_tile_recal_due( fd_clock_tile_t * clock ) {
  return fd_clock_tile_now( clock ) >= fd_clock_tile_recal_next( clock );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_fd_clock_tile_h */
