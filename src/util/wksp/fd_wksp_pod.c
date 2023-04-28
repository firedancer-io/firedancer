#include "fd_wksp_private.h"

uchar const *
fd_wksp_pod_attach( char const * gaddr ) {
  if( FD_UNLIKELY( !gaddr ) ) FD_LOG_ERR(( "NULL gaddr" ));

  void * obj = fd_wksp_map( gaddr );
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "Unable to map pod at gaddr %s into local address space", gaddr ));

  uchar const * pod = fd_pod_join( obj );
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "fd_pod_join to pod at gaddr %s failed", gaddr ));

  return pod;
}

void
fd_wksp_pod_detach( uchar const * pod ) {
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "NULL pod" ));

  void * obj = fd_pod_leave( pod );
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "fd_pod_leave failed" ));

  fd_wksp_unmap( obj ); /* logs details */
}

void *
fd_wksp_pod_map( uchar const * pod,
                 char const *  path ) {
  if( FD_UNLIKELY( !pod  ) ) FD_LOG_ERR(( "NULL pod"  ));
  if( FD_UNLIKELY( !path ) ) FD_LOG_ERR(( "NULL path" ));

  char const * gaddr = fd_pod_query_cstr( pod, path, NULL );
  if( FD_UNLIKELY( !gaddr ) ) FD_LOG_ERR(( "cstr path %s not found in pod", path ));

  void * obj = fd_wksp_map( gaddr );
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "Unable to map pod cstr path %s (%s) into local address space", path, gaddr ));

  return obj;
}

void
fd_wksp_pod_unmap( void * obj ) {
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "NULL obj" ));

  fd_wksp_unmap( obj ); /* logs details */
}

