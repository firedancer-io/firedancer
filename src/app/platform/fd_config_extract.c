#include "fd_config_extract.h"

/* Find leftover ******************************************************/

/* fdctl_pod_find_leftover recursively searches for non-subpod keys in
   pod.  Prints to the warning log if it finds any.  Used to detect
   config keys that were not recognized by fdctl.  Returns 0 if no
   leftover key was found.  Otherwise, returns a non-zero number of
   segments of the leftover key.  The key can be reassembled by joining
   stack[0] .. stack[depth-1].

   Not thread safe (uses global buffer). */

# define FDCTL_CFG_MAX_DEPTH (16)

static ulong
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
