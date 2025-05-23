#include "fd_config_parse.h"

int
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

int
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

int
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

int
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

int
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

/* Find leftover ******************************************************/

/* fdctl_pod_find_leftover recursively searches for non-subpod keys in
   pod.  Prints to the warning log if it finds any.  Used to detect
   config keys that were not recognized by fdctl.  Returns 0 if no
   leftover key was found.  Otherwise, returns a non-zero number of
   segments of the leftover key.  The key can be reassembled by joining
   stack[0] .. stack[depth-1].

   Not thread safe (uses global buffer). */

# define FDCTL_CFG_MAX_DEPTH (16)

ulong
fdctl_pod_find_leftover_recurse( uchar *       pod,
                                 char const ** stack,
                                 ulong         depth ) {

  if( FD_UNLIKELY( depth+1 >= FDCTL_CFG_MAX_DEPTH ) ) {
    FD_LOG_WARNING(( "configuration file has too many nested keys" ));
    return depth;
  }

  for( fd_pod_iter_t iter = fd_pod_iter_init( pod ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    stack[ depth ] = info.key;
    depth++;
    if( FD_LIKELY( info.val_type == FD_POD_VAL_TYPE_SUBPOD ) ) {
      ulong sub_depth = fdctl_pod_find_leftover_recurse( (uchar *)info.val, stack, depth );
      if( FD_UNLIKELY( sub_depth ) ) return sub_depth;
    } else {
      return depth;
    }
    depth--;
  }

  return 0;
}

int
fdctl_pod_find_leftover( uchar * pod ) {

  static char const * stack[ FDCTL_CFG_MAX_DEPTH ];
  ulong depth = fdctl_pod_find_leftover_recurse( pod, stack, 0UL );
  if( FD_LIKELY( !depth ) ) return 1;

  static char path[ 64*FDCTL_CFG_MAX_DEPTH + 4 ];
  char * c   = fd_cstr_init( path );
  char * end = path + 64*FDCTL_CFG_MAX_DEPTH - 1;
  for( ulong j=0UL; j<depth; j++ ) {
    char const * key     = stack[j];
    ulong        key_len = strlen( key );
    if( c+key_len+1 >= end ) {
      c = fd_cstr_append_text( c, "...", 3UL );
      break;
    }
    c = fd_cstr_append_text( c, key, key_len );
    c = fd_cstr_append_char( c, '.' );
  }
  c -= 1;
  fd_cstr_fini( c );

  FD_LOG_WARNING(( "Config file contains unrecognized key `%s`", path ));
  return 0;
}

#undef CFG_POP
#undef CFG_ARRAY
