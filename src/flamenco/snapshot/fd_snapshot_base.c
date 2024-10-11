#include "fd_snapshot_base.h"

#include <stdlib.h>

fd_snapshot_name_t *
fd_snapshot_name_from_buf( fd_snapshot_name_t * id,
                           char const *         str,
                           ulong                str_len,
                           ulong                base_slot ) {
  char buf[ 4096 ];
  str_len = fd_ulong_min( sizeof(buf)-1, str_len );
  fd_memcpy( buf, str, str_len );
  buf[ str_len ] = '\0';

  return fd_snapshot_name_from_cstr( id, buf, base_slot );
}

fd_snapshot_name_t *
fd_snapshot_name_from_cstr( fd_snapshot_name_t * id,
                            char const *         cstr,
                            ulong                base_slot ) {

  fd_memset( id, 0, sizeof(fd_snapshot_name_t) );

  const char * orig_cstr = cstr;

  char * last_slash = strrchr( cstr, '/' );
  if( last_slash && last_slash[0]=='/' ) cstr = last_slash + 1;

  if( 0==strncmp( cstr, "snapshot-", sizeof("snapshot-")-1 ) ) {
    cstr += sizeof("snapshot-")-1;
    id->type = FD_SNAPSHOT_TYPE_FULL;
  } else if( 0==strncmp( cstr, "incremental-snapshot-", sizeof("incremental-snapshot-")-1 ) ) {
    cstr += sizeof("incremental-snapshot-")-1;
    id->type = FD_SNAPSHOT_TYPE_INCREMENTAL;
  } else {
    FD_LOG_WARNING(( "unrecognized snapshot type: \"%s\"", orig_cstr ));
    return NULL;
  }

  char const * endptr = NULL;
  id->slot = strtoul( cstr, fd_type_pun( &endptr ), 10 );
  if( !endptr || endptr[0]!='-' ) {
    FD_LOG_WARNING(( "invalid snapshot file name: \"%s\"", orig_cstr ));
    return NULL;
  }
  cstr = endptr+1;

  if( id->type == FD_SNAPSHOT_TYPE_INCREMENTAL ) {
    id->incremental_slot = strtoul( cstr, fd_type_pun( &endptr ), 10 );
    if( !endptr || endptr[0]!='-' ) {
      FD_LOG_WARNING(( "invalid snapshot file name: \"%s\"", orig_cstr ));
      return NULL;
    }
    cstr = endptr+1;

    if( base_slot != id->slot ) {
      FD_LOG_WARNING(( "failed to load snapshot: \"%s\"", orig_cstr ));
      FD_LOG_WARNING(( "expected base slot %lu but got %lu, incremental snapshot does not match full snapshot", base_slot, id->slot ));
      return NULL;
    }
  }

  char const * file_ext = strchr( cstr, '.' );
  ulong        file_ext_off = (ulong)( file_ext - cstr );

  char hash_cstr[ FD_BASE58_ENCODED_32_SZ ] = {0};
  strncpy( hash_cstr, cstr, sizeof(hash_cstr)-1 );
  if( file_ext_off < sizeof(hash_cstr) ) {
    hash_cstr[ file_ext_off ] = '\0';
  }
  strncpy( id->file_ext, file_ext, sizeof(id->file_ext)-1 );

  if( FD_UNLIKELY( !fd_base58_decode_32( hash_cstr, id->fhash.hash ) ) ) {
    FD_LOG_WARNING(( "invalid snapshot file name: \"%s\"", orig_cstr ));
    return NULL;
  }
  return id;
}
