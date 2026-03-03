#include "fd_vinyl.h"

ulong
fd_vinyl_align( void ) {
  return alignof(fd_vinyl_t);
}

ulong
fd_vinyl_footprint( void ) {
  return sizeof(fd_vinyl_t);
}

void *
fd_vinyl_fini( fd_vinyl_t * vinyl ) {

  if( FD_UNLIKELY( !vinyl ) ) {
    FD_LOG_WARNING(( "NULL vinyl" ));
    return NULL;
  }

  /* Note: does not sync.  App should decide if sync is appropriate
     before calling fini. */

  fd_vinyl_data_fini( vinyl->data );

  void * _meta = fd_vinyl_meta_shmap( vinyl->meta );
  fd_vinyl_meta_leave( vinyl->meta );
  fd_vinyl_meta_delete( _meta );

  fd_cnc_delete( fd_cnc_leave( vinyl->cnc ) );

  return vinyl;
}

char *
fd_vinyl_cnc_signal_cstr( ulong  signal,
                          char * buf ) {
  if( FD_LIKELY( buf ) ) {
    switch( signal ) {
    case FD_VINYL_CNC_SIGNAL_RUN:          strcpy( buf, "run"          ); break;
    case FD_VINYL_CNC_SIGNAL_BOOT:         strcpy( buf, "boot"         ); break;
    case FD_VINYL_CNC_SIGNAL_FAIL:         strcpy( buf, "fail"         ); break;
    case FD_VINYL_CNC_SIGNAL_HALT:         strcpy( buf, "halt"         ); break;
    case FD_VINYL_CNC_SIGNAL_SYNC:         strcpy( buf, "sync"         ); break;
    case FD_VINYL_CNC_SIGNAL_GET:          strcpy( buf, "get"          ); break;
    case FD_VINYL_CNC_SIGNAL_SET:          strcpy( buf, "set"          ); break;
    case FD_VINYL_CNC_SIGNAL_CLIENT_JOIN:  strcpy( buf, "client_join"  ); break;
    case FD_VINYL_CNC_SIGNAL_CLIENT_LEAVE: strcpy( buf, "client_leave" ); break;
    default:                               fd_cstr_printf( buf, FD_VINYL_CNC_SIGNAL_CSTR_BUF_MAX, NULL, "%lu", signal ); break;
    }
  }
  return buf;
}
