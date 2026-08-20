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
  uchar hash[ FD_HASH_FOOTPRINT ];
};
typedef struct fd_ssarchive_entry fd_ssarchive_entry_t;

#define SORT_NAME  sort_ssarchive_entries
#define SORT_KEY_T fd_ssarchive_entry_t
#define SORT_BEFORE(a,b) ( (a).slot>(b).slot )
#include "../../../util/tmpl/fd_sort.c"

static fd_ssarchive_entry_t *
ssarchive_entry_insert( fd_ssarchive_entry_t * entries,
                        ulong *                cnt,
                        ulong                  slot ) {
  if( FD_LIKELY( *cnt<FD_SSARCHIVE_MAX_ENTRIES ) ) return &entries[ (*cnt)++ ];

  ulong oldest = 0UL;
  for( ulong i=1UL; i<*cnt; i++ ) {
    if( entries[ i ].slot<entries[ oldest ].slot ) oldest = i;
  }
  if( FD_UNLIKELY( slot<=entries[ oldest ].slot ) ) return NULL;
  return &entries[ oldest ];
}

int
fd_ssarchive_latest_pair( char const * directory,
                          int          incremental_snapshot,
                          ulong *      full_slot,
                          ulong *      incremental_slot,
                          char         full_path[ static PATH_MAX ],
                          char         incremental_path[ static PATH_MAX ],
                          int *        full_is_zstd,
                          int *        incremental_is_zstd,
                          uchar        full_hash[ static FD_HASH_FOOTPRINT ],
                          uchar        incremental_hash[ static FD_HASH_FOOTPRINT ] ) {
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
  for(;;) {
    errno = 0;
    entry = readdir( dir );
    if( FD_UNLIKELY( !entry ) ) break;
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    int is_zstd;
    ulong entry_full_slot, entry_incremental_slot;
    uchar decoded_hash[ FD_HASH_FOOTPRINT ];
    if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot, decoded_hash, &is_zstd ) ) ) {
      FD_LOG_INFO(( "unrecognized snapshot file `%s/%s` in snapshots directory", directory, entry->d_name ));
      continue;
    }

    fd_ssarchive_entry_t * dst;
    ulong                  dst_slot;
    ulong                  dst_base_slot;
    if( FD_LIKELY( entry_incremental_slot==ULONG_MAX ) ) {
      dst_slot      = entry_full_slot;
      dst_base_slot = ULONG_MAX;
      dst           = ssarchive_entry_insert( full_snapshots, &full_snapshots_cnt, dst_slot );
    } else {
      dst_slot      = entry_incremental_slot;
      dst_base_slot = entry_full_slot;
      dst           = ssarchive_entry_insert( incremental_snapshots, &incremental_snapshots_cnt, dst_slot );
    }
    if( FD_UNLIKELY( !dst ) ) {
      FD_LOG_INFO(( "more than %lu snapshots of one kind in `%s`, ignoring `%s`",
                    FD_SSARCHIVE_MAX_ENTRIES, directory, entry->d_name ));
      continue;
    }

    dst->slot      = dst_slot;
    dst->base_slot = dst_base_slot;
    dst->is_zstd   = is_zstd;
    if( FD_UNLIKELY( !fd_cstr_printf_check( dst->path, PATH_MAX, NULL, "%s/%s", directory, entry->d_name ) ) ) {
      FD_LOG_ERR(( "snapshot path too long `%s/%s`", directory, entry->d_name ));
    }
    fd_memcpy( dst->hash, decoded_hash, FD_HASH_FOOTPRINT );
  }

  if( FD_UNLIKELY( errno ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( incremental_snapshot ) ) {
    if( FD_UNLIKELY( incremental_snapshots_cnt==0UL && full_snapshots_cnt==0UL ) ) return -1;
    if( FD_UNLIKELY( full_snapshots_cnt==0UL ) )                                   return -1;

    sort_ssarchive_entries_inplace( incremental_snapshots, incremental_snapshots_cnt );
    sort_ssarchive_entries_inplace( full_snapshots, full_snapshots_cnt );

    if( FD_UNLIKELY( incremental_snapshots_cnt==0UL ) ) {
      FD_LOG_INFO(("no incremental snapshots found in `%s`, falling back to latest full snapshot", directory ));
      *full_slot           = full_snapshots[ 0UL ].slot;
      *full_is_zstd        = full_snapshots[ 0UL ].is_zstd;
      *incremental_slot    = ULONG_MAX;
      *incremental_is_zstd = 0;
      FD_TEST( fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s", full_snapshots[ 0UL ].path ) );
      incremental_path[ 0UL ] = '\0';
      fd_memcpy( full_hash, full_snapshots[ 0UL ].hash, FD_HASH_FOOTPRINT );
      memset( incremental_hash, 0, FD_HASH_FOOTPRINT );
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
          fd_memcpy( full_hash, full_snapshots[ j ].hash, FD_HASH_FOOTPRINT );
          fd_memcpy( incremental_hash, incremental_snapshots[ i ].hash, FD_HASH_FOOTPRINT );
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
    incremental_path[ 0UL ] = '\0';
    fd_memcpy( full_hash, full_snapshots[ 0UL ].hash, FD_HASH_FOOTPRINT );
    memset( incremental_hash, 0, FD_HASH_FOOTPRINT );
    return 0;

  } else {
    if( FD_UNLIKELY( full_snapshots_cnt==0UL ) ) return -1;

    sort_ssarchive_entries_inplace( full_snapshots, full_snapshots_cnt );

    *full_slot           = full_snapshots[ 0UL ].slot;
    *full_is_zstd        = full_snapshots[ 0UL ].is_zstd;
    *incremental_slot    = ULONG_MAX;
    *incremental_is_zstd = 0;
    FD_TEST( fd_cstr_printf_check( full_path, PATH_MAX, NULL, "%s", full_snapshots[ 0UL ].path ) );
    incremental_path[ 0UL ] = '\0';
    fd_memcpy( full_hash, full_snapshots[ 0UL ].hash, FD_HASH_FOOTPRINT );
    memset( incremental_hash, 0, FD_HASH_FOOTPRINT );
    return 0;
  }
}

int
fd_ssarchive_latest_best( char const * directory,
                          int          incremental_snapshot,
                          ulong        target_slot,
                          ulong *      full_slot,
                          ulong *      incremental_slot,
                          char         full_path[ static PATH_MAX ],
                          char         incremental_path[ static PATH_MAX ],
                          int *        full_is_zstd,
                          int *        incremental_is_zstd,
                          uchar        full_hash[ static FD_HASH_FOOTPRINT ],
                          uchar        incremental_hash[ static FD_HASH_FOOTPRINT ] ) {

  int found = 0==fd_ssarchive_latest_pair( directory,
                                           0,
                                           full_slot,
                                           incremental_slot,
                                           full_path,
                                           incremental_path,
                                           full_is_zstd,
                                           incremental_is_zstd,
                                           full_hash,
                                           incremental_hash );

  /* An incremental has to pair with a full, so without one there is
     nothing left to look for: the pair search fails on the same
     condition. */

  if( FD_UNLIKELY( !found ) ) return -1;

  /* Consider the pair when incrementals are enabled, or when the full
     alone falls short of the target. */

  if( FD_UNLIKELY( !incremental_snapshot && !( target_slot && *full_slot<target_slot ) ) ) return 0;

  ulong pair_full_slot = ULONG_MAX;
  ulong pair_incr_slot = ULONG_MAX;
  int   pair_full_zstd = 0;
  int   pair_incr_zstd = 0;
  char  pair_full_path[ PATH_MAX ] = {0};
  char  pair_incr_path[ PATH_MAX ] = {0};
  uchar pair_full_hash[ FD_HASH_FOOTPRINT ] = {0};
  uchar pair_incr_hash[ FD_HASH_FOOTPRINT ] = {0};

  if( FD_UNLIKELY( 0!=fd_ssarchive_latest_pair( directory,
                                                1,
                                                &pair_full_slot,
                                                &pair_incr_slot,
                                                pair_full_path,
                                                pair_incr_path,
                                                &pair_full_zstd,
                                                &pair_incr_zstd,
                                                pair_full_hash,
                                                pair_incr_hash ) ) ) {
    return 0;
  }

  ulong pair_slot = fd_ulong_if( pair_incr_slot!=ULONG_MAX, pair_incr_slot, pair_full_slot );
  if( FD_LIKELY( pair_slot>*full_slot ) ) {
    *full_slot           = pair_full_slot;
    *incremental_slot    = pair_incr_slot;
    *full_is_zstd        = pair_full_zstd;
    *incremental_is_zstd = pair_incr_zstd;
    fd_memcpy( full_path,        pair_full_path, PATH_MAX );
    fd_memcpy( incremental_path, pair_incr_path, PATH_MAX );
    fd_memcpy( full_hash,        pair_full_hash, FD_HASH_FOOTPRINT );
    fd_memcpy( incremental_hash, pair_incr_hash, FD_HASH_FOOTPRINT );
  }

  return 0;
}
