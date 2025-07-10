#include "fd_ssarchive.h"

#include "../../../util/log/fd_log.h"

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>

/* Parses a snapshot filename like

    incremental-snapshot-344185432-344209085-45eJ5C91fEenPRFc8NiqaDXMCHcPFwRUTMH3k1zY6a1B.tar.zst
    snapshot-344185432-BSP9ztdFEjwvkBo2LhHA47g9Q3PDwja9x5fj7taFRKH5.tar.zst

   into components.  Returns one of FD_SSARCHIVE_PARSE_*.  On success
   the snapshot will be either a FULL or INCREMENTAL parse result.  If
   incremental, the incremental slot will be set to ULONG_MAX, otherwise
   it is set to the incremental slot number.  On success, the full slot
   and the snapshot hash are always set.  The hash will be the base58
   decoded hash. */

int
fd_ssarchive_parse( char const * filename,
                    ulong *      full_slot,
                    ulong *      incremental_slot,
                    uchar        hash[ static 32UL ] );

static int
parse_filename( char *  _name,
                ulong * full_slot,
                ulong * incremental_slot ) {
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
    if( FD_UNLIKELY( -1==parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot ) ) ) {
      FD_LOG_WARNING(( "unrecognized snapshot file `%s/%s` in snapshots directory", directory, entry->d_name ));
      continue;
    }

    if( FD_LIKELY( *full_slot==ULONG_MAX || entry_full_slot>*full_slot ) ) {
      *full_slot = entry_full_slot;
      if( FD_UNLIKELY( !fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) ) ) {
        FD_LOG_ERR(( "snapshot path too long `%s/%s`", directory, entry->d_name ));
      }
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( !incremental_snapshot ) ) return 0;
  if( FD_UNLIKELY( *full_slot==ULONG_MAX ) ) return -1;

  dir = opendir( directory );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return 0;
    FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", directory, errno, fd_io_strerror( errno ) ));
  }

  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    ulong entry_full_slot, entry_incremental_slot;
    if( FD_UNLIKELY( -1==parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot ) ) ) continue;

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
