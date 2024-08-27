#include "fd_hcache_private.h"

#include <stdarg.h>
#include <stdio.h>
#include <poll.h>

FD_FN_CONST ulong
fd_hcache_align( void ) {
  return FD_HCACHE_ALIGN;
}

FD_FN_CONST ulong
fd_hcache_footprint( ulong data_sz ) {
  return fd_ulong_align_up( 128UL + data_sz, FD_HCACHE_ALIGN );
}

void *
fd_hcache_new( void *             shmem,
               fd_http_server_t * server,
               ulong              data_sz ) {
  fd_hcache_t * hcache = (fd_hcache_t *)shmem;

  if( FD_UNLIKELY( !hcache ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)hcache, FD_HCACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    return NULL;
  }

  hcache->server = server;

  hcache->snap_off = 0UL;
  hcache->snap_len = 0UL;
  hcache->snap_err = 0;
  hcache->data_sz  = data_sz;

  ulong footprint = fd_hcache_footprint( data_sz );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad data_sz" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hcache->magic ) = FD_HCACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return hcache;
}

fd_hcache_t *
fd_hcache_join( void * shhcache ) {
  fd_hcache_t * hcache = (fd_hcache_t *)shhcache;

  if( FD_UNLIKELY( !hcache ) ) {
    FD_LOG_WARNING(( "NULL shhcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)hcache, FD_HCACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    return NULL;
  }

  if( FD_UNLIKELY( hcache->magic!=FD_HCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return hcache;
}

void *
fd_hcache_leave( fd_hcache_t * hcache ) {
  if( FD_UNLIKELY( !hcache ) ) {
    FD_LOG_WARNING(( "NULL hcache" ));
    return NULL;
  }

  return (void *)hcache;
}

void *
fd_hcache_delete( void * shhcache ) {
  fd_hcache_t * hcache = (fd_hcache_t *)shhcache;

  if( FD_UNLIKELY( !hcache ) ) {
    FD_LOG_WARNING(( "NULL shhcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)hcache, FD_HCACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "bad align" ));
    return NULL;
  }

  if( FD_UNLIKELY( hcache->magic!=FD_HCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hcache->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return hcache;
}

FD_FN_PURE ulong
fd_hcache_data_sz( fd_hcache_t * hcache ) {
  return hcache->data_sz;
}

static void
fd_hcache_evict_conns( fd_hcache_t * hcache,
                       ulong         snap_off,
                       ulong         snap_len ) {
  for( ulong i=0UL; i<hcache->server->max_conns; i++ ) {
    if( FD_LIKELY( hcache->server->pollfds[ i ].fd==-1 ) ) continue;

    struct fd_http_server_connection * conn = hcache->server->conns + i;
    int evict = conn->response.body>=fd_hcache_private_data( hcache )+snap_off &&
                conn->response.body<fd_hcache_private_data( hcache )+snap_off+snap_len;

    if( FD_UNLIKELY( evict ) ) fd_http_server_close( hcache->server, i, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
  }

  for( ulong i=0UL; i<hcache->server->max_ws_conns; i++ ) {
    if( FD_LIKELY( hcache->server->pollfds[ hcache->server->max_conns+i ].fd==-1 ) ) continue;

    struct fd_http_server_ws_connection * conn = hcache->server->ws_conns + i;
    if( FD_UNLIKELY( conn->send_frame_cnt ) ) {
      int evict = conn->send_frames[ conn->send_frame_idx ].data>=fd_hcache_private_data( hcache )+snap_off &&
                  conn->send_frames[ conn->send_frame_idx ].data<fd_hcache_private_data( hcache )+snap_off+snap_len;

      if( FD_UNLIKELY( evict ) ) fd_http_server_ws_close( hcache->server, i, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
    }
  }
}

static void
fd_hcache_reserve( fd_hcache_t * hcache,
                   ulong         len ) {
  ulong remaining = hcache->data_sz - (hcache->snap_off + hcache->snap_len);
  if( FD_UNLIKELY( len>remaining ) ) {
    /* Appending the format string into the hcache would go past the end
        of the buffer... two cases, */
    if( FD_UNLIKELY( hcache->snap_len+len>hcache->data_sz ) ) {
      /* Case 1: The snap is going to be larger than the entire buffer,
                  there's no way to fit it even if we evict everything
                  else.  Mark the hcache as errored and exit. */
      hcache->snap_err = 1;
      return;
    } else {
      /* Case 2: The snap can fit if we relocate it to the start of the
                 buffer and evict whatever was there.  We also evict the
                 rest of the buffer behind where the snap was to
                 preserve the invariant that snaps are always evicted in
                 circular order. */
      fd_hcache_evict_conns( hcache, hcache->snap_off+hcache->snap_len, remaining );
      fd_hcache_evict_conns( hcache, 0UL, hcache->snap_len+len );
      memmove( fd_hcache_private_data( hcache ),
               fd_hcache_private_data( hcache ) + hcache->snap_off,
               hcache->snap_len );
      hcache->snap_off = 0UL;
    }
  } else {
    /* The snap can fit in the buffer, we just need to evict whatever
        was there before. */
    fd_hcache_evict_conns( hcache, hcache->snap_off+hcache->snap_len, len );
  }
}

void
fd_hcache_printf( fd_hcache_t * hcache,
                  char const *  fmt,
                  ... ) {
  if( FD_UNLIKELY( hcache->snap_err ) ) return;

  va_list ap;
  va_start( ap, fmt );
  ulong printed_len = (ulong)vsnprintf( NULL, 0UL, fmt, ap );
  va_end( ap );

  fd_hcache_reserve( hcache, printed_len );

  va_start( ap, fmt );
  vsnprintf( (char *)fd_hcache_private_data( hcache ) + hcache->snap_off + hcache->snap_len,
             INT_MAX, /* We already proved it's going to fit above */
             fmt,
             ap );
  va_end( ap );

  hcache->snap_len += printed_len;
}

void
fd_hcache_memcpy( fd_hcache_t * hcache,
                  uchar const * data,
                  ulong         data_len ) {
  fd_hcache_reserve( hcache, data_len );
  if( FD_UNLIKELY( hcache->snap_err ) ) return;

  fd_memcpy( (char *)fd_hcache_private_data( hcache )+hcache->snap_off+hcache->snap_len,
             data,
             data_len );
  hcache->snap_len += data_len;
}

void
fd_hcache_reset( fd_hcache_t * hcache ) {
  hcache->snap_len = 0;
  hcache->snap_err = 0;
}

uchar const *
fd_hcache_snap_response( fd_hcache_t * hcache,
                         ulong *       body_len ) {
  if( FD_UNLIKELY( hcache->snap_err ) ) {
    hcache->snap_err = 0;
    hcache->snap_off = 0UL;
    hcache->snap_len = 0UL;
    return NULL;
  }

  *body_len          = hcache->snap_len;
  uchar const * body = fd_hcache_private_data( hcache ) + hcache->snap_off;

  hcache->snap_off = (hcache->snap_off + hcache->snap_len) % hcache->data_sz;
  hcache->snap_len = 0UL;
  return body;
}

int
fd_hcache_snap_ws_send( fd_hcache_t * hcache,
                        ulong         ws_conn_id ) {
  if( FD_UNLIKELY( hcache->snap_err ) ) {
    hcache->snap_err = 0;
    hcache->snap_off = 0UL;
    hcache->snap_len = 0UL;
    return -1;
  }

  fd_http_server_ws_frame_t frame = {
    .data     = fd_hcache_private_data( hcache ) + hcache->snap_off,
    .data_len = hcache->snap_len,
  };
  fd_http_server_ws_send( hcache->server, ws_conn_id, frame );

  hcache->snap_off = (hcache->snap_off + hcache->snap_len) % hcache->data_sz;
  hcache->snap_len = 0UL;
  return 0;
}


int
fd_hcache_snap_ws_broadcast( fd_hcache_t * hcache ) {
  if( FD_UNLIKELY( hcache->snap_err ) ) {
    hcache->snap_err = 0;
    hcache->snap_off = 0UL;
    hcache->snap_len = 0UL;
    return -1;
  }

  fd_http_server_ws_frame_t frame = {
    .data     = fd_hcache_private_data( hcache ) + hcache->snap_off,
    .data_len = hcache->snap_len,
  };
  fd_http_server_ws_broadcast( hcache->server, frame );

  hcache->snap_off = (hcache->snap_off + hcache->snap_len) % hcache->data_sz;
  hcache->snap_len = 0UL;
  return 0;
}
