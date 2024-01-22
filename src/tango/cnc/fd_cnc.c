#include "fd_cnc.h"

ulong
fd_cnc_align( void ) {
  return FD_CNC_ALIGN;
}

ulong
fd_cnc_footprint( ulong app_sz ) {
  if( FD_UNLIKELY( app_sz > (ULONG_MAX-191UL) ) ) return 0UL; /* overflow */
  return FD_CNC_FOOTPRINT( app_sz );
}

void *
fd_cnc_new( void * shmem,
            ulong  app_sz,
            ulong  type,
            long   now ) {
  fd_cnc_t * cnc = (fd_cnc_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_cnc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_cnc_footprint( app_sz );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad app_sz (%lu)", app_sz ));
    return NULL;
  }

  fd_memset( cnc, 0, footprint );

  cnc->app_sz     = app_sz;
  cnc->type       = type;
  cnc->heartbeat0 = now;
  cnc->heartbeat  = now;
  cnc->lock       = 0UL;
  cnc->signal     = FD_CNC_SIGNAL_BOOT;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc->magic ) = FD_CNC_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)cnc;
}

fd_cnc_t *
fd_cnc_join( void * shcnc ) {

  if( FD_UNLIKELY( !shcnc ) ) {
    FD_LOG_WARNING(( "NULL shcnc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shcnc, fd_cnc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shcnc" ));
    return NULL;
  }

  fd_cnc_t * cnc = (fd_cnc_t *)shcnc;

  if( FD_UNLIKELY( cnc->magic!=FD_CNC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return cnc;
}

void *
fd_cnc_leave( fd_cnc_t const * cnc ) {

  if( FD_UNLIKELY( !cnc ) ) {
    FD_LOG_WARNING(( "NULL cnc" ));
    return NULL;
  }

  return (void *)cnc; /* Kinda ugly const cast */
}

void *
fd_cnc_delete( void * shcnc ) {

  if( FD_UNLIKELY( !shcnc ) ) {
    FD_LOG_WARNING(( "NULL shcnc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shcnc, fd_cnc_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shcnc" ));
    return NULL;
  }

  fd_cnc_t * cnc = (fd_cnc_t *)shcnc;

  if( FD_UNLIKELY( cnc->magic!=FD_CNC_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)cnc;
}

#if FD_HAS_HOSTED && FD_HAS_ATOMIC

#include <errno.h>
#include <signal.h>
#include <sched.h>

int
fd_cnc_open( fd_cnc_t * cnc ) {

  /* Check input args */

  if( FD_UNLIKELY( !cnc ) ) {
    FD_LOG_WARNING(( "NULL cnc" ));
    return FD_CNC_ERR_INVAL;
  }

  ulong my_pid = fd_log_group_id();
  if( FD_UNLIKELY( (!my_pid) | (my_pid!=(ulong)(pid_t)my_pid) ) ) {
    FD_LOG_WARNING(( "unexpected pid (%lu)", my_pid ));
    return FD_CNC_ERR_UNSUP;
  }

  /* Try to acquire a lock on the cnc */

  FD_COMPILER_MFENCE();
  ulong cnc_pid = FD_ATOMIC_CAS( &cnc->lock, 0UL, my_pid );
  FD_COMPILER_MFENCE();

  if( FD_LIKELY( !cnc_pid ) ) {

    /* Got the lock ... get the status of the app thread. */

    ulong signal = fd_cnc_signal_query( cnc );

    /* If the app thread was in the run state, return success. */

    if( FD_LIKELY( signal==FD_CNC_SIGNAL_RUN ) ) return FD_CNC_SUCCESS;

    /* At this point, since RUN was not observed, we can't safely issue
       signals to the app thread.  So we unlock the lock.  If FAIL was
       observed, we know that this thread is permanently dead and we
       hard fail the open request.  If BOOT, HALT or USER defined, we
       can't guarantee that we will never be able to open up a command
       session, so we tell the user to try again later. */

    FD_COMPILER_MFENCE();
    FD_VOLATILE( cnc->lock ) = 0UL;
    FD_COMPILER_MFENCE();

    if( FD_LIKELY( signal==FD_CNC_SIGNAL_FAIL ) ) {
      FD_LOG_WARNING(( "app thread failed; unable to open command session" ));
      return FD_CNC_ERR_FAIL;
    }

    char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
    FD_LOG_WARNING(( "signal %s (%lu) in progress on app thread; try again later?", fd_cnc_signal_cstr( signal, buf ), signal ));
    return FD_CNC_ERR_AGAIN;
  }

  /* Somebody else seems to have an open command session on the app
     thread.  Check that the somebody else is alive. */

  if( FD_UNLIKELY( cnc_pid!=my_pid && kill( (pid_t)cnc_pid, 0 ) ) ) {

    int err = errno;
    if( FD_LIKELY( err==ESRCH ) ) {

      /* A process died with an open command session.  Try to clean up
         after it and resume. */

      if( FD_LIKELY( FD_ATOMIC_CAS( &cnc->lock, cnc_pid, my_pid )==cnc_pid ) ) {

        /* We successfully reclaimed the lock from the dead process.  If
           there is a pending signal from it still being processed by
           the app thread (e.g. HALT or USER defined), wait briefly for
           it complete and then decide how best to proceed.  (Note: this
           assumes no pid reuse between the kill above cas.) */

        ulong signal = fd_cnc_signal_query( cnc );

        if( FD_UNLIKELY( !( (signal==FD_CNC_SIGNAL_BOOT) | (signal==FD_CNC_SIGNAL_RUN ) | (signal==FD_CNC_SIGNAL_FAIL) ) ) )
          signal = fd_cnc_wait( cnc, signal, (ulong)100e6, NULL ); /* 100 ms */

        if( FD_LIKELY( signal==FD_CNC_SIGNAL_RUN ) ) {

          /* App thread seem to be running and we have the lock.  Looks
             like we can recover. */

          FD_LOG_WARNING(( "pid %lu died with an open command session; attempting to recover", cnc_pid ));
          return FD_CNC_SUCCESS;
        }

        if( FD_LIKELY( signal==FD_CNC_SIGNAL_BOOT ) ) {

          /* Last signal apparently stopped the app thread and left it
             in a state where it can be booted again safely.  Unlock the
             session lock to end the stale command session (so that the
             thread can be booted again) and fail this open request with
             try again later as this open might succeed in the future
             (i.e. after the thread is booted in the run state again). */

          FD_COMPILER_MFENCE();
          FD_VOLATILE( cnc->lock ) = 0UL;
          FD_COMPILER_MFENCE();

          FD_LOG_WARNING(( "pid %lu died with an open command session that cleanly halted the app thread; try again later?",
                           cnc_pid ));
          return FD_CNC_ERR_AGAIN;
        }

        if( FD_LIKELY( signal==FD_CNC_SIGNAL_FAIL ) ) {

          /* Last signal apparently stopped the app thread and left it
             in a state where it cannot be booted again safely.  Unlock
             the session lock to end the stale command session (so that
             the app thread can be cleaned up) and fail this open
             request. */

          FD_COMPILER_MFENCE();
          FD_VOLATILE( cnc->lock ) = 0UL;
          FD_COMPILER_MFENCE();

          FD_LOG_WARNING(( "pid %lu died with an open command session that uncleanly halted the app thread", cnc_pid ));
          return FD_CNC_ERR_FAIL;
        }

        /* App thread seems to be still processing a HALT or USER
           defined signal.  Restore the lock to the dead pid and tell
           the user to try again later (when we might know better how to
           recover). */

        FD_COMPILER_MFENCE();
        FD_VOLATILE( cnc->lock ) = cnc_pid;
        FD_COMPILER_MFENCE();

        FD_LOG_WARNING(( "pid %lu died with an open command session and last signal issued (%lu) still seems to be pending; "
                         "try again later?", cnc_pid, signal ));
        return FD_CNC_ERR_AGAIN;
      }

      /* Another thread reclaimed the lock before we could.  Presumably
         that thread will recover the lock so we tell the user to try
         again later. */

      FD_LOG_WARNING(( "pid %lu died with an open command session and another thread is trying to clean it up; try again later?",
                       cnc_pid ));
      return FD_CNC_ERR_AGAIN;
    }

    /* There is an open command session but we can't tell if the pid
       running it is live.  Assume it is and tell the user to try again
       later. */

    FD_LOG_WARNING(( "pid %lu currently command session and unable to diagnose pid's state (%i-%s); try again later?",
                     cnc_pid, err, fd_io_strerror( err ) ));
    return FD_CNC_ERR_AGAIN;
  }

  /* There is already an open command session from a seemingly live
     process */

  FD_LOG_WARNING(( "pid %lu currently has an open command session; try again later?", cnc_pid ));
  return FD_CNC_ERR_AGAIN;
}

#else

int
fd_cnc_open( fd_cnc_t * cnc ) {
  (void)cnc;
  FD_LOG_WARNING(( "unsupported for this build target" ));
  return FD_CNC_ERR_UNSUP;
}

#endif

ulong
fd_cnc_wait( fd_cnc_t const * cnc,
             ulong            test,
             long             dt,
             long *           _opt_now ) {
  long then = fd_log_wallclock();
  long now  = then;

  ulong obs;
  for(;;) {
    obs = fd_cnc_signal_query( cnc );
    int done = ((obs!=test) | ((now-then)>dt));
    FD_COMPILER_FORGET( done ); /* avoid compiler misoptimization */
    if( FD_LIKELY( done ) ) break; /* optimize for exit, single exit to optimize spin pause hinting */
    FD_YIELD();
    now = fd_log_wallclock();
  }

  if( _opt_now ) *_opt_now = now; /* usage dep prob */
  return obs;
}

char const *
fd_cnc_strerror( int err ) {
  switch( err ) {
  case FD_CNC_SUCCESS:   return "success";
  case FD_CNC_ERR_UNSUP: return "unsupported here";
  case FD_CNC_ERR_INVAL: return "bad inputs";
  case FD_CNC_ERR_AGAIN: return "try again later";
  case FD_CNC_ERR_FAIL:  return "app thread failed";
  default: break;
  }
  return "unknown---possibly not a cnc error code";
}

ulong
fd_cstr_to_cnc_signal( char const * cstr ) {
  if( FD_UNLIKELY( !cstr ) ) return FD_CNC_SIGNAL_RUN;
  if( !fd_cstr_casecmp( cstr, "run"  ) ) return FD_CNC_SIGNAL_RUN;
  if( !fd_cstr_casecmp( cstr, "boot" ) ) return FD_CNC_SIGNAL_BOOT;
  if( !fd_cstr_casecmp( cstr, "fail" ) ) return FD_CNC_SIGNAL_FAIL;
  if( !fd_cstr_casecmp( cstr, "halt" ) ) return FD_CNC_SIGNAL_HALT;
  return fd_cstr_to_ulong( cstr );
}

char *
fd_cnc_signal_cstr( ulong  signal,
                    char * buf ) {
  if( FD_LIKELY( buf ) ) {
    switch( signal ) {
    case FD_CNC_SIGNAL_RUN:  strcpy( buf, "run"  ); break;
    case FD_CNC_SIGNAL_BOOT: strcpy( buf, "boot" ); break;
    case FD_CNC_SIGNAL_FAIL: strcpy( buf, "fail" ); break;
    case FD_CNC_SIGNAL_HALT: strcpy( buf, "halt" ); break;
    default:                 fd_cstr_printf( buf, FD_CNC_SIGNAL_CSTR_BUF_MAX, NULL, "%lu", signal ); break;
    }
  }
  return buf;
}
