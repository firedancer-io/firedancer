#ifndef HEADER_fd_src_app_platform_fd_config_extract_h
#define HEADER_fd_src_app_platform_fd_config_extract_h

#include "../../util/fd_util.h"
#include "../../util/pod/fd_pod.h"

FD_PROTOTYPES_BEGIN

/* fdctl_pod_find_leftover recursively descends a pod and logs a
   WARNING for each remaining leaf item.  Intended for warning the user
   about unrecognized config options, after loading config files into a
   pod. */

int
fdctl_pod_find_leftover( uchar * pod );

/* Pod query utils ****************************************************/

static inline int
fdctl_cfg_get_cstr_( char *                out,
                     ulong                 out_sz,
                     fd_pod_info_t const * info,
                     char const *          path ) {
  if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_CSTR ) ) {
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
  char const * str = info->val;
  ulong        sz  = strlen( str ) + 1;
  if( FD_UNLIKELY( sz > out_sz ) ) {
    FD_LOG_WARNING(( "`%s`: too long (max %ld)", path, (long)out_sz-1L ));
    return 0;
  }
  fd_memcpy( out, str, sz );
  return 1;
}

#define fdctl_cfg_get_cstr( out, out_sz, info, path ) \
  fdctl_cfg_get_cstr_( *out, out_sz, info, path )

static inline int
fdctl_cfg_get_ulong( ulong *               out,
                     ulong                 out_sz FD_PARAM_UNUSED,
                     fd_pod_info_t const * info,
                     char const *          path ) {

  ulong num;
  switch( info->val_type ) {
  case FD_POD_VAL_TYPE_LONG:
    fd_ulong_svw_dec( (uchar const *)info->val, &num );
    long snum = fd_long_zz_dec( num );
    if( snum < 0L ) {
      FD_LOG_WARNING(( "`%s` cannot be negative", path ));
      return 0;
    }
    num = (ulong)snum;
    break;
  case FD_POD_VAL_TYPE_ULONG:
    fd_ulong_svw_dec( (uchar const *)info->val, &num );
    break;
  default:
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }

  *out = num;
  return 1;
}

static inline int
fdctl_cfg_get_uint( uint *                out,
                    ulong                 out_sz FD_PARAM_UNUSED,
                    fd_pod_info_t const * info,
                    char const *          path ) {
  ulong num;
  if( FD_UNLIKELY( !fdctl_cfg_get_ulong( &num, sizeof(num), info, path ) ) ) return 0;
  if( num > UINT_MAX ) {
    FD_LOG_WARNING(( "`%s` is out of bounds (%lx)", path, num ));
    return 0;
  }
  *out = (uint)num;
  return 1;
}

static inline int
fdctl_cfg_get_ushort( ushort *              out,
                      ulong                 out_sz FD_PARAM_UNUSED,
                      fd_pod_info_t const * info,
                      char const *          path ) {
  ulong num;
  if( FD_UNLIKELY( !fdctl_cfg_get_ulong( &num, sizeof(num), info, path ) ) ) return 0;
  if( num > USHORT_MAX ) {
    FD_LOG_WARNING(( "`%s` is out of bounds (%lx)", path, num ));
    return 0;
  }
  *out = (ushort)num;
  return 1;
}

static inline int
fdctl_cfg_get_bool( int *                 out,
                    ulong                 out_sz FD_PARAM_UNUSED,
                    fd_pod_info_t const * info,
                    char const *          path ) {
  if( FD_UNLIKELY( info->val_type != FD_POD_VAL_TYPE_INT ) ) {
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
  ulong u; fd_ulong_svw_dec( (uchar const *)info->val, &u );
  *out = fd_int_zz_dec( (uint)u );
  return 1;
}

static inline int
fdctl_cfg_get_float( float *               out,
                     ulong                 out_sz FD_PARAM_UNUSED,
                     fd_pod_info_t const * info,
                     char const *          path ) {

  ulong unum;
  float num;
  switch( info->val_type ) {
  case FD_POD_VAL_TYPE_LONG:
    fd_ulong_svw_dec( (uchar const *)info->val, &unum );
    long snum = fd_long_zz_dec( unum );
    if( snum < 0L ) {
      FD_LOG_WARNING(( "`%s` cannot be negative", path ));
      return 0;
    }
    num = (float)snum;
    break;
  case FD_POD_VAL_TYPE_ULONG:
    fd_ulong_svw_dec( (uchar const *)info->val, &unum );
    num = (float)unum;
    break;
  case FD_POD_VAL_TYPE_FLOAT:
    num = FD_LOAD( float, info->val );
    break;
  default:
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }

  *out = num;
  return 1;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_platform_fd_config_extract_h */
