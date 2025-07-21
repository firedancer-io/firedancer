#include "fd_ssarchive.h"

#include "../../../util/log/fd_log.h"

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>

int
fd_ssarchive_parse_filename( char *  _name,
                             ulong * full_slot,
                             ulong * incremental_slot,
                             uchar   hash[ static FD_HASH_FOOTPRINT ] ) {
  char name[ PATH_MAX ] = {0};
  strncpy( name, _name, PATH_MAX-1 );

  char * ptr = name;
  int is_incremental;
  if( !strncmp( ptr, "incremental-snapshot-", 21UL ) ) {
    is_incremental = 1;
    ptr += 21UL;
  } else if( !strncmp( ptr, "snapshot-", 9UL ) ) {
    is_incremental = 0;
    ptr += 9UL;
  } else {
    return -1;
  }

  char * next = strchr( ptr, '-' );
  if( FD_UNLIKELY( !next ) ) return -1;

  *next = '\0';
  char * endptr;
  ulong slot = strtoul( ptr, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!='\0' || slot==ULONG_MAX ) ) return -1;

  *full_slot = slot;

  if( is_incremental ) {
    ptr = next + 1;
    next = strchr( ptr, '-' );
    if( FD_UNLIKELY( !next ) ) return -1;

    *next = '\0';
    slot = strtoul( ptr, &endptr, 10 );
    if( FD_UNLIKELY( *endptr!='\0' || slot==ULONG_MAX ) ) return -1;

    *incremental_slot = slot;
  } else {
    *incremental_slot = ULONG_MAX;
  }

  ptr = next + 1;
  next = strchr( ptr, '.' );
  if( FD_UNLIKELY( !next ) ) return -1;

  ulong sz = (ulong)(next - ptr);

  if( FD_UNLIKELY( sz>FD_BASE58_ENCODED_32_LEN ) ) return -1;

  char encoded_hash[ FD_BASE58_ENCODED_32_SZ ];
  fd_memcpy( encoded_hash, ptr, sz );
  encoded_hash[ sz ] = '\0';
  uchar * result = fd_base58_decode_32( encoded_hash, hash );

  if( FD_UNLIKELY( !result ) ) return -1;

  if( FD_UNLIKELY( strncmp( next, ".tar.zst", 8UL ) ) ) return -1;
  return 0;
}

int
fd_ssarchive_latest_pair( char const * directory,
                          int          incremental_snapshot,
                          ulong *      full_slot,
                          ulong *      incremental_slot,
                          char         full_path[ static PATH_MAX ],
                          char         incremental_path[ static PATH_MAX ] ) {
  *full_slot = ULONG_MAX;
  *incremental_slot = ULONG_MAX;

  DIR * dir = opendir( directory );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return -1;
    FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", directory, errno, fd_io_strerror( errno ) ));
  }

  struct dirent * entry;

  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    ulong entry_full_slot, entry_incremental_slot;
    uchar decoded_hash[ FD_HASH_FOOTPRINT ];
    if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot, decoded_hash ) ) ) {
      FD_LOG_WARNING(( "unrecognized snapshot file `%s/%s` in snapshots directory", directory, entry->d_name ));
      continue;
    }

    if( FD_LIKELY( entry_incremental_slot==ULONG_MAX && (entry_full_slot>*full_slot || *full_slot==ULONG_MAX) ) ) {
      *full_slot = entry_full_slot;
      if( FD_UNLIKELY( !fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) ) ) {
        FD_LOG_ERR(( "snapshot path too long `%s/%s`", directory, entry->d_name ));
      }
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( *full_slot==ULONG_MAX ) ) return -1;
  if( FD_UNLIKELY( !incremental_snapshot ) ) return 0;

  dir = opendir( directory );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return 0;
    FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", directory, errno, fd_io_strerror( errno ) ));
  }

  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    ulong entry_full_slot, entry_incremental_slot;
    uchar decoded_hash[ FD_HASH_FOOTPRINT ];
    if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot, decoded_hash ) ) ) continue;

    if( FD_UNLIKELY( entry_incremental_slot==ULONG_MAX || *full_slot!=entry_full_slot ) ) continue;

    if( FD_LIKELY( *incremental_slot==ULONG_MAX || entry_incremental_slot>*incremental_slot ) ) {
      *incremental_slot = entry_incremental_slot;
      if( FD_UNLIKELY( !fd_cstr_printf_check( incremental_path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) ) ) {
        FD_LOG_ERR(( "snapshot path too long `%s/%s`", directory, entry->d_name ));
      }
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return 0;
}
