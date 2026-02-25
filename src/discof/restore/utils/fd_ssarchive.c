#include "fd_ssarchive.h"

#include "../../../util/log/fd_log.h"

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

struct fd_ssarchive_entry {
  ulong slot;
  ulong base_slot;
  int   is_zstd;
  char  path[ PATH_MAX ];
};
typedef struct fd_ssarchive_entry fd_ssarchive_entry_t;

#define SORT_NAME  sort_ssarchive_entries
#define SORT_KEY_T fd_ssarchive_entry_t
#define SORT_BEFORE(a,b) ( (a).slot>(b).slot )
#include "../../../util/tmpl/fd_sort.c"

#define FD_SSARCHIVE_MAX_ENTRIES (512UL)

int
fd_ssarchive_parse_filename( char const * _name,
                             ulong *      full_slot,
                             ulong *      incremental_slot,
                             uchar        hash[ static FD_HASH_FOOTPRINT ],
                             int *        is_zstd ) {
  char name[ PATH_MAX ];
  fd_cstr_ncpy( name, _name, sizeof(name) );

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
  *full_slot = strtoul( ptr, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!='\0' || endptr==ptr || *full_slot==ULONG_MAX ) ) return -1;

  if( is_incremental ) {
    ptr = next + 1;
    next = strchr( ptr, '-' );
    if( FD_UNLIKELY( !next ) ) return -1;
    *next = '\0';
    *incremental_slot = strtoul( ptr, &endptr, 10 );
    if( FD_UNLIKELY( *endptr!='\0' || endptr==ptr || *incremental_slot==ULONG_MAX ) ) return -1;
  } else {
    *incremental_slot = ULONG_MAX;
  }

  ptr = next + 1;
  next = strchr( ptr, '.' );
  if( FD_UNLIKELY( !next ) ) return -1;
  *next = '\0';
  ulong sz = (ulong)(next - ptr);
  if( FD_UNLIKELY( sz>FD_BASE58_ENCODED_32_LEN ) ) return -1;
  uchar * result = fd_base58_decode_32( ptr, hash );
  if( FD_UNLIKELY( result!=hash ) ) return -1;

  ptr = next + 1;

  if(       FD_LIKELY( 0==strcmp( ptr, "tar.zst" ) ) ) *is_zstd = 1;
  else if ( FD_LIKELY( 0==strcmp( ptr, "tar"     ) ) ) *is_zstd = 0;
  else return -1;

  return 0;
}

int
fd_ssarchive_latest_pair( char const * directory,
                          int          incremental_snapshot,
                          ulong *      full_slot,
                          ulong *      incremental_slot,
                          char         full_path[ static PATH_MAX ],
                          char         incremental_path[ static PATH_MAX ],
                          int *        full_is_zstd,
                          int *        incremental_is_zstd ) {
  *full_slot = ULONG_MAX;
  *incremental_slot = ULONG_MAX;

  DIR * dir = opendir( directory );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return -1;
    FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", directory, errno, fd_io_strerror( errno ) ));
  }

  fd_ssarchive_entry_t full_snapshots[ FD_SSARCHIVE_MAX_ENTRIES ];
  fd_ssarchive_entry_t incremental_snapshots[ FD_SSARCHIVE_MAX_ENTRIES ];
  ulong full_snapshots_cnt        = 0UL;
  ulong incremental_snapshots_cnt = 0UL;

  struct dirent * entry;
  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    int is_zstd;
    ulong entry_full_slot, entry_incremental_slot;
    uchar decoded_hash[ FD_HASH_FOOTPRINT ];
    if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot, decoded_hash, &is_zstd ) ) ) {
      FD_LOG_INFO(( "unrecognized snapshot file `%s/%s` in snapshots directory", directory, entry->d_name ));
      continue;
    }

    if( FD_LIKELY( entry_incremental_slot==ULONG_MAX ) ) {
      if( FD_UNLIKELY( full_snapshots_cnt>=FD_SSARCHIVE_MAX_ENTRIES ) ) {
        continue;
      }

      full_snapshots[ full_snapshots_cnt ].slot      = entry_full_slot;
      full_snapshots[ full_snapshots_cnt ].base_slot = ULONG_MAX;
      full_snapshots[ full_snapshots_cnt ].is_zstd   = is_zstd;
      if( FD_UNLIKELY( !fd_cstr_printf_check( full_snapshots[ full_snapshots_cnt ].path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) ) ) {
        FD_LOG_ERR(( "snapshot path too long `%s/%s`", directory, entry->d_name ));
      }
      full_snapshots_cnt++;
    } else {
      if( FD_UNLIKELY( incremental_snapshots_cnt>=FD_SSARCHIVE_MAX_ENTRIES ) ) {
        continue;
      }

      incremental_snapshots[ incremental_snapshots_cnt ].slot      = entry_incremental_slot;
      incremental_snapshots[ incremental_snapshots_cnt ].base_slot = entry_full_slot;
      incremental_snapshots[ incremental_snapshots_cnt ].is_zstd   = is_zstd;
      if( FD_UNLIKELY( !fd_cstr_printf_check( incremental_snapshots[ incremental_snapshots_cnt ].path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) ) ) {
        FD_LOG_ERR(( "snapshot path too long `%s/%s`", directory, entry->d_name ));
      }
      incremental_snapshots_cnt++;
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( incremental_snapshot ) ) {
    if( FD_UNLIKELY( incremental_snapshots_cnt==0UL && full_snapshots_cnt==0UL ) ) return -1;
    if( FD_UNLIKELY( full_snapshots_cnt==0UL ) )                                   return -1;

    sort_ssarchive_entries_inplace( incremental_snapshots, incremental_snapshots_cnt );
    sort_ssarchive_entries_inplace( full_snapshots, full_snapshots_cnt );

    if( FD_UNLIKELY( incremental_snapshots_cnt==0UL ) ) {
      FD_LOG_WARNING(("no incremental snapshots found in `%s`, falling back to latest full snapshot", directory ));
      *full_slot           = full_snapshots[ 0UL ].slot;
      *full_is_zstd        = full_snapshots[ 0UL ].is_zstd;
      *incremental_slot    = ULONG_MAX;
      *incremental_is_zstd = 0;
      FD_TEST( fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s", full_snapshots[ 0UL ].path ) );
      return 0;
    }

    for( ulong i=0UL; i<incremental_snapshots_cnt; i++ ) {
      ulong base_slot = incremental_snapshots[ i ].base_slot;
      for( ulong j=0; j<full_snapshots_cnt; j++ ) {
        if( FD_LIKELY( full_snapshots[ j ].slot==base_slot ) ) {
          *full_slot           = base_slot;
          *incremental_slot    = incremental_snapshots[ i ].slot;
          *full_is_zstd        = full_snapshots[ j ].is_zstd;
          *incremental_is_zstd = incremental_snapshots[ i ].is_zstd;
          FD_TEST( fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s", full_snapshots[ j ].path ) );
          FD_TEST( fd_cstr_printf_check( incremental_path, PATH_MAX, NULL, "%s", incremental_snapshots[ i ].path ) );
          return 0;
        } else if( FD_LIKELY( full_snapshots[ j ].slot<base_slot ) ) {
            /* full snapshots are sorted in descending order, so if we reach a
               full snapshot with slot smaller than the incremental snapshot's
               base slot, we can stop searching.  */
            break;
        }
      }
    }

    /* if we reach here, it means all incrementals are dangling (they
       don't build off any full snapshot). fallback to a full
       snapshot in that case. */
    *full_slot           = full_snapshots[ 0UL ].slot;
    *full_is_zstd        = full_snapshots[ 0UL ].is_zstd;
    *incremental_slot    = ULONG_MAX;
    *incremental_is_zstd = 0;
    FD_TEST( fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s", full_snapshots[ 0UL ].path ) );
    return 0;

  } else {
    if( FD_UNLIKELY( full_snapshots_cnt==0UL ) ) return -1;

    sort_ssarchive_entries_inplace( full_snapshots, full_snapshots_cnt );

    *full_slot           = full_snapshots[ 0UL ].slot;
    *full_is_zstd        = full_snapshots[ 0UL ].is_zstd;
    *incremental_slot    = ULONG_MAX;
    *incremental_is_zstd = 0;
    FD_TEST( fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s", full_snapshots[ 0UL ].path ) );
    return 0;
  }
}

void
fd_ssarchive_remove_old_snapshots( char const * directory,
                                   uint         max_full_snapshots_to_keep,
                                   uint         max_incremental_snapshots_to_keep ) {
  ulong full_snapshots_cnt        = 0UL;
  ulong incremental_snapshots_cnt = 0UL;
  fd_ssarchive_entry_t full_snapshots[ FD_SSARCHIVE_MAX_ENTRIES ];
  fd_ssarchive_entry_t incremental_snapshots[ FD_SSARCHIVE_MAX_ENTRIES ];

  DIR * dir = opendir( directory );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return;
    FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", directory, errno, fd_io_strerror( errno ) ));
  }

  struct dirent * entry;

  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    int is_zstd;
    ulong entry_full_slot, entry_incremental_slot;
    uchar decoded_hash[ FD_HASH_FOOTPRINT ];
    if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot, decoded_hash, &is_zstd ) ) ) {
      FD_LOG_INFO(( "unrecognized snapshot file `%s/%s` in snapshots directory", directory, entry->d_name ));
      continue;
    }

    if( FD_LIKELY( entry_incremental_slot==ULONG_MAX ) ) {
      FD_TEST( entry_full_slot!=ULONG_MAX );

      if( FD_UNLIKELY( full_snapshots_cnt>=FD_SSARCHIVE_MAX_ENTRIES ) ) {
        continue;
      }

      full_snapshots[ full_snapshots_cnt ].slot      = entry_full_slot;
      full_snapshots[ full_snapshots_cnt ].base_slot = ULONG_MAX;
      full_snapshots[ full_snapshots_cnt ].is_zstd   = is_zstd;
      FD_TEST( fd_cstr_printf_check( full_snapshots[ full_snapshots_cnt ].path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) );
      full_snapshots_cnt++;
    } else {

      if( FD_UNLIKELY( incremental_snapshots_cnt>=FD_SSARCHIVE_MAX_ENTRIES ) ) {
        continue;
      }

      incremental_snapshots[ incremental_snapshots_cnt ].slot      = entry_incremental_slot;
      incremental_snapshots[ incremental_snapshots_cnt ].base_slot = entry_full_slot;
      incremental_snapshots[ incremental_snapshots_cnt ].is_zstd   = is_zstd;
      FD_TEST( fd_cstr_printf_check( incremental_snapshots[ incremental_snapshots_cnt ].path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) );
      incremental_snapshots_cnt++;
    }
  }

  if( FD_UNLIKELY( errno && errno!=ENOENT ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( full_snapshots_cnt>max_full_snapshots_to_keep ) ) {
    sort_ssarchive_entries_inplace( full_snapshots, full_snapshots_cnt );
    for( ulong i=max_full_snapshots_to_keep; i<full_snapshots_cnt; i++ ) {
      if( FD_UNLIKELY( -1==unlink( full_snapshots[ i ].path ) ) ) {
        FD_LOG_ERR(( "unlink(%s) failed (%i-%s)", full_snapshots[ i ].path, errno, fd_io_strerror( errno ) ));
      }
    }
  }

  if( FD_LIKELY( incremental_snapshots_cnt>max_incremental_snapshots_to_keep ) ) {
    sort_ssarchive_entries_inplace( incremental_snapshots, incremental_snapshots_cnt );
    for( ulong i=max_incremental_snapshots_to_keep; i<incremental_snapshots_cnt; i++ ) {
      if( FD_UNLIKELY( -1==unlink( incremental_snapshots[ i ].path ) ) ) {
        FD_LOG_ERR(( "unlink(%s) failed (%i-%s)", incremental_snapshots[ i ].path, errno, fd_io_strerror( errno ) ));
      }
    }
  }
}
