#ifndef HEADER_fd_src_disco_topo_fd_pod_format_h
#define HEADER_fd_src_disco_topo_fd_pod_format_h

#include "../../util/pod/fd_pod.h"

#include <stdarg.h>
#include <stdio.h>

/* fd_pod_insertf_[type] inserts the [type] val into the pod at the
   given path.  The path is constructed from the given format string.
   Returns offset where val was inserted, 0 on failure.  The inserted
   representation might be compressed.  This offset is valid for the
   pod's lifetime or an invalidating operation is done on the pod.

   IMPORTANT!  THIS IS AN INVALIDATING OPERATION */

#define FD_POD_IMPL(type,TYPE)                                                  \
static inline ulong                                                             \
fd_pod_insertf_##type( uchar      * FD_RESTRICT pod,                            \
                       type                     val,                            \
                       char const * FD_RESTRICT fmt, ... ) {                    \
  va_list ap;                                                                   \
  va_start( ap, fmt );                                                          \
  char buf[ 128UL ];                                                            \
  int   ret = vsnprintf( buf, 128UL, fmt, ap );                                 \
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 128UL-1UL ) ); \
  buf[ len ] = '\0';                                                            \
  va_end( ap );                                                                 \
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;                   \
  return fd_pod_insert_##type( pod, buf, val );                                 \
}

FD_POD_IMPL( ushort, USHORT )
FD_POD_IMPL( uint,   UINT   )
FD_POD_IMPL( ulong,  ULONG  )
FD_POD_IMPL( short,  SHORT )
FD_POD_IMPL( int,    INT   )
FD_POD_IMPL( long,   LONG  )
FD_POD_IMPL( char,   CHAR   )
FD_POD_IMPL( schar,  SCHAR  )
FD_POD_IMPL( uchar,  UCHAR  )
FD_POD_IMPL( float,  FLOAT  )
#if FD_HAS_DOUBLE
FD_POD_IMPL( double, DOUBLE )
#endif

#undef FD_POD_IMPL

static inline ulong
fd_pod_insertf_cstr( uchar      * FD_RESTRICT pod,
                     char const * FD_RESTRICT str,
                     char const * FD_RESTRICT fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  char buf[ 128UL ];
  int   ret = vsnprintf( buf, 128UL, fmt, ap );
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 128UL-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;
  return fd_pod_insert_cstr( pod, buf, str );
}

/* fd_pod_replacef_[type] replaces the [type] val into the pod at the
   given path.  The path is constructed from the given format string.
   If the path does not exist, it is created.  Returns FD_POD_SUCCESS
   on success, or FD_POD_ERR_* on failure.

   IMPORTANT!  THIS IS AN INVALIDATING OPERATION */

#define FD_POD_IMPL(type,TYPE)                                                  \
static inline int                                                               \
fd_pod_replacef_##type( uchar      * FD_RESTRICT pod,                           \
                        type                     val,                           \
                        char const * FD_RESTRICT fmt, ... ) {                   \
  va_list ap;                                                                   \
  va_start( ap, fmt );                                                          \
  char buf[ 128UL ];                                                            \
  int   ret = vsnprintf( buf, 128UL, fmt, ap );                                 \
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 128UL-1UL ) ); \
  buf[ len ] = '\0';                                                            \
  va_end( ap );                                                                 \
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;                   \
  int result = fd_pod_remove( pod, buf );                                       \
  if( FD_UNLIKELY( result!=FD_POD_SUCCESS && result!=FD_POD_ERR_RESOLVE ) )     \
    return result;                                                              \
  if( FD_UNLIKELY( !fd_pod_insert_##type( pod, buf, val ) ) )                   \
    return FD_POD_ERR_FULL;                                                     \
  return FD_POD_SUCCESS;                                                        \
}

FD_POD_IMPL( ushort, USHORT )
FD_POD_IMPL( uint,   UINT   )
FD_POD_IMPL( ulong,  ULONG  )
FD_POD_IMPL( short,  SHORT )
FD_POD_IMPL( int,    INT   )
FD_POD_IMPL( long,   LONG  )
FD_POD_IMPL( char,   CHAR   )
FD_POD_IMPL( schar,  SCHAR  )
FD_POD_IMPL( uchar,  UCHAR  )
FD_POD_IMPL( float,  FLOAT  )
#if FD_HAS_DOUBLE
FD_POD_IMPL( double, DOUBLE )
#endif

#undef FD_POD_IMPL

/* fd_pod_queryf_[type] queries for the [type] in pod at path.  The path
   is constructed from the given format string.  Returns the query
   result on success or def on failure. */

#define FD_POD_IMPL(type,TYPE)                                                  \
static inline type                                                              \
fd_pod_queryf_##type( uchar const * FD_RESTRICT  pod,                           \
                      type                       def,                           \
                      char const   * FD_RESTRICT fmt, ... ) {                   \
  va_list ap;                                                                   \
  va_start( ap, fmt );                                                          \
  char buf[ 128UL ];                                                            \
  int   ret = vsnprintf( buf, 128UL, fmt, ap );                                 \
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 128UL-1UL ) ); \
  buf[ len ] = '\0';                                                            \
  va_end( ap );                                                                 \
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;                   \
  return fd_pod_query_##type( pod, buf, def );                                  \
}

FD_POD_IMPL( ushort, USHORT )
FD_POD_IMPL( uint,   UINT   )
FD_POD_IMPL( ulong,  ULONG  )
FD_POD_IMPL( short,  SHORT )
FD_POD_IMPL( int,    INT   )
FD_POD_IMPL( long,   LONG  )
FD_POD_IMPL( char,   CHAR   )
FD_POD_IMPL( schar,  SCHAR  )
FD_POD_IMPL( uchar,  UCHAR  )
FD_POD_IMPL( float,  FLOAT  )
#if FD_HAS_DOUBLE
FD_POD_IMPL( double, DOUBLE )
#endif

#undef FD_POD_IMPL

static inline char const *
fd_pod_queryf_cstr( uchar const * FD_RESTRICT pod,
                    char const  * FD_RESTRICT def,
                    char const  * FD_RESTRICT fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  char buf[ 128UL ];
  int   ret = vsnprintf( buf, 128UL, fmt, ap );
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 128UL-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=128UL ) ) return 0UL;
  return fd_pod_query_cstr( pod, buf, def );
}

#endif /* HEADER_fd_src_disco_topo_fd_pod_format_h */
