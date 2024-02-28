#ifndef HEADER_fd_src_disco_topo_fd_topo_pod_helper_h
#define HEADER_fd_src_disco_topo_fd_topo_pod_helper_h

#include <stdarg.h>

#define FD_POD_IMPL(type,TYPE)                                               \
static inline ulong                                                          \
fd_pod_insertf_##type( uchar      * FD_RESTRICT pod,                         \
                       type                     val,                         \
                       char const * FD_RESTRICT fmt, ... ) {                 \
  va_list ap;                                                                \
  va_start( ap, fmt );                                                       \
  char buf[ 64 ];                                                            \
  int   ret = vsnprintf( buf, 64, fmt, ap );                                 \
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 64-1UL ) ); \
  buf[ len ] = '\0';                                                         \
  va_end( ap );                                                              \
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=64 ) ) return 0UL;                   \
  return fd_pod_insert_##type( pod, buf, val );                              \
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
                     char const * FD_RESTRICT path, ... ) {
  va_list ap;
  va_start( ap, path );
  char buf[ 64 ];
  int   ret = vsnprintf( buf, 64, path, ap );
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 64-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=64 ) ) return 0UL;
  return fd_pod_insert_cstr( pod, buf, str );
}

#define FD_POD_IMPL(type,TYPE)                                               \
static inline ulong                                                          \
fd_pod_replacef_##type( uchar      * FD_RESTRICT pod,                        \
                        type                     val,                        \
                        char const * FD_RESTRICT path, ... ) {               \
  va_list ap;                                                                \
  va_start( ap, path );                                                      \
  char buf[ 64 ];                                                            \
  int   ret = vsnprintf( buf, 64, path, ap );                                \
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 64-1UL ) ); \
  buf[ len ] = '\0';                                                         \
  va_end( ap );                                                              \
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=64 ) ) return 0UL;                   \
  int result = fd_pod_remove( pod, buf );                                    \
  FD_TEST( !result || result==FD_POD_ERR_RESOLVE );                          \
  return fd_pod_insert_##type( pod, buf, val );                              \
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

#define FD_POD_IMPL(type,TYPE)                                               \
static inline type                                                           \
fd_pod_queryf_##type( uchar const * FD_RESTRICT pod,                         \
                      type                     def,                          \
                      char const   * FD_RESTRICT path, ... ) {               \
  va_list ap;                                                                \
  va_start( ap, path );                                                      \
  char buf[ 64 ];                                                            \
  int   ret = vsnprintf( buf, 64, path, ap );                                \
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 64-1UL ) ); \
  buf[ len ] = '\0';                                                         \
  va_end( ap );                                                              \
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=64 ) ) return 0UL;                   \
  return fd_pod_query_##type( pod, buf, def );                               \
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
                    char const  * FD_RESTRICT path, ... ) {
  va_list ap;
  va_start( ap, path );
  char buf[ 64 ];
  int   ret = vsnprintf( buf, 64, path, ap );
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, 64-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( FD_UNLIKELY( ret<0 || (ulong)ret>=64 ) ) return 0UL;
  return fd_pod_query_cstr( pod, buf, def );
}

#endif /* HEADER_fd_src_util_topo_fd_topo_pod_helper_h */
