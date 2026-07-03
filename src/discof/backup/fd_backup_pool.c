#define _GNU_SOURCE
#include "fd_backup_pool.h"
#include "fd_backup.h"
#include "../restore/utils/fd_ssarchive.h"
#include "../../util/log/fd_log.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct pool_entry {
  ulong slot;
  char  name[ FD_BACKUP_NAME_MAX ];
};

typedef struct pool_entry pool_entry_t;

#define SORT_NAME  sort_pool_entries
#define SORT_KEY_T pool_entry_t
#define SORT_BEFORE(a,b) ( (a).slot>(b).slot )
#include "../../util/tmpl/fd_sort.c"

#define POOL_SCAN_MAX (512UL)

char *
fd_backup_pool_partial_name( char name[ static FD_BACKUP_POOL_PARTIAL_NAME_MAX ],
                             uint slot_idx ) {
  FD_TEST( fd_cstr_printf_check( name, FD_BACKUP_POOL_PARTIAL_NAME_MAX, NULL, "snapshot%u.partial", slot_idx ) );
  return name;
}

/* is_pool_artifact returns 1 if name is a producer-owned scratch file:
   a "snapshot<i>.partial" placeholder or a legacy "*.wip" work file.
   These are unlinked (and placeholders recreated as needed) on boot. */

static int
is_pool_artifact( char const * name ) {
  ulong len = strlen( name );
  if( len>=4UL && !strcmp( name+len-4UL, ".wip" ) ) return 1;

  if( strncmp( name, "snapshot", 8UL ) ) return 0;
  char const * p = name+8UL;
  if( *p<'0' || *p>'9' ) return 0;
  while( *p>='0' && *p<='9' ) p++;
  return 0==strcmp( p, ".partial" );
}

void
fd_backup_pool_boot( char const * snapshots_path,
                     uint         max_full_snapshots_to_keep,
                     uint         max_incremental_snapshots_to_keep,
                     uint         uid,
                     uint         gid ) {
  uint pool_cnt = max_full_snapshots_to_keep+max_incremental_snapshots_to_keep;
  if( FD_UNLIKELY( !max_full_snapshots_to_keep ) )
    FD_LOG_ERR(( "[snapshots.max_full_snapshots_to_keep] must be at least 1 when snapshot creation is enabled" ));
  if( FD_UNLIKELY( pool_cnt>FD_BACKUP_POOL_MAX ) )
    FD_LOG_ERR(( "[snapshots.max_full_snapshots_to_keep] plus [snapshots.max_incremental_snapshots_to_keep] "
                 "must not exceed %u when snapshot creation is enabled", FD_BACKUP_POOL_MAX ));

  int dir_fd = open( snapshots_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  if( FD_UNLIKELY( -1==dir_fd ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", snapshots_path, errno, fd_io_strerror( errno ) ));

  /* Scan the directory: collect existing snapshots, unlink leftover
     producer artifacts.  Unrecognized files are left alone. */

  pool_entry_t full_snapshots[ POOL_SCAN_MAX ];
  pool_entry_t incremental_snapshots[ POOL_SCAN_MAX ];
  ulong full_snapshots_cnt        = 0UL;
  ulong incremental_snapshots_cnt = 0UL;

  DIR * dir = opendir( snapshots_path );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", snapshots_path, errno, fd_io_strerror( errno ) ));

  struct dirent * entry;
  for(;;) {
    errno = 0;
    entry = readdir( dir );
    if( FD_UNLIKELY( !entry ) ) break;
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    if( FD_UNLIKELY( is_pool_artifact( entry->d_name ) ) ) {
      if( FD_UNLIKELY( -1==unlinkat( dir_fd, entry->d_name, 0 ) ) )
        FD_LOG_ERR(( "unlinkat(%s/%s) failed (%i-%s)", snapshots_path, entry->d_name, errno, fd_io_strerror( errno ) ));
      continue;
    }

    int is_zstd;
    ulong entry_full_slot, entry_incremental_slot;
    uchar decoded_hash[ FD_HASH_FOOTPRINT ];
    if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &entry_full_slot, &entry_incremental_slot, decoded_hash, &is_zstd ) ) ) continue;
    if( FD_UNLIKELY( strlen( entry->d_name )>=FD_BACKUP_NAME_MAX ) ) continue;

    if( FD_LIKELY( entry_incremental_slot==ULONG_MAX ) ) {
      if( FD_UNLIKELY( full_snapshots_cnt>=POOL_SCAN_MAX ) ) continue;
      full_snapshots[ full_snapshots_cnt ].slot = entry_full_slot;
      fd_cstr_ncpy( full_snapshots[ full_snapshots_cnt ].name, entry->d_name, FD_BACKUP_NAME_MAX );
      full_snapshots_cnt++;
    } else {
      if( FD_UNLIKELY( incremental_snapshots_cnt>=POOL_SCAN_MAX ) ) continue;
      incremental_snapshots[ incremental_snapshots_cnt ].slot = entry_incremental_slot;
      fd_cstr_ncpy( incremental_snapshots[ incremental_snapshots_cnt ].name, entry->d_name, FD_BACKUP_NAME_MAX );
      incremental_snapshots_cnt++;
    }
  }

  if( FD_UNLIKELY( errno ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  sort_pool_entries_inplace( full_snapshots, full_snapshots_cnt );
  sort_pool_entries_inplace( incremental_snapshots, incremental_snapshots_cnt );

  for( ulong i=max_full_snapshots_to_keep; i<full_snapshots_cnt; i++ ) {
    if( FD_UNLIKELY( -1==unlinkat( dir_fd, full_snapshots[ i ].name, 0 ) ) )
      FD_LOG_ERR(( "unlinkat(%s/%s) failed (%i-%s)", snapshots_path, full_snapshots[ i ].name, errno, fd_io_strerror( errno ) ));
  }
  for( ulong i=max_incremental_snapshots_to_keep; i<incremental_snapshots_cnt; i++ ) {
    if( FD_UNLIKELY( -1==unlinkat( dir_fd, incremental_snapshots[ i ].name, 0 ) ) )
      FD_LOG_ERR(( "unlinkat(%s/%s) failed (%i-%s)", snapshots_path, incremental_snapshots[ i ].name, errno, fd_io_strerror( errno ) ));
  }

  /* Assign the kept snapshots to their slots (fulls in [0,max_full),
     incrementals in [max_full,pool_cnt), newest first), create empty
     placeholders for the unassigned slots, and open the pool fds. */

  for( uint i=0U; i<pool_cnt; i++ ) {
    char partial_name[ FD_BACKUP_POOL_PARTIAL_NAME_MAX ];
    char const * name = NULL;
    if( FD_LIKELY( i<max_full_snapshots_to_keep ) ) {
      if( i<full_snapshots_cnt ) name = full_snapshots[ i ].name;
    } else {
      uint j = i-max_full_snapshots_to_keep;
      if( j<incremental_snapshots_cnt ) name = incremental_snapshots[ j ].name;
    }

    if( FD_UNLIKELY( !name ) ) {
      name = fd_backup_pool_partial_name( partial_name, i );
      int fd = openat( dir_fd, name, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644 );
      if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "openat(%s/%s) failed (%i-%s)", snapshots_path, name, errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( !getuid() && -1==fchown( fd, uid, gid ) ) )
        FD_LOG_ERR(( "fchown(%s/%s) failed (%i-%s)", snapshots_path, name, errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    int buf_fd = openat( dir_fd, name, O_WRONLY );
    if( FD_UNLIKELY( -1==buf_fd ) ) FD_LOG_ERR(( "openat(%s/%s) failed (%i-%s)", snapshots_path, name, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==dup2( buf_fd, FD_BACKUP_POOL_FD( i ) ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( buf_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    int dio_fd = openat( dir_fd, name, O_WRONLY|O_DIRECT );
    if( FD_UNLIKELY( -1==dio_fd ) ) FD_LOG_ERR(( "openat(%s/%s, O_DIRECT) failed (%i-%s)", snapshots_path, name, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==dup2( dio_fd, FD_BACKUP_POOL_DIO_FD( i ) ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( -1==close( dio_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( -1==close( dir_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
fd_backup_pool_recover( char const *            snapshots_path,
                        uint                    pool_cnt,
                        fd_backup_pool_slot_t * slot ) {
  FD_TEST( pool_cnt && pool_cnt<=FD_BACKUP_POOL_MAX );

  struct stat pool_st[ FD_BACKUP_POOL_MAX ];
  int         found  [ FD_BACKUP_POOL_MAX ] = {0};
  for( uint i=0U; i<pool_cnt; i++ ) {
    if( FD_UNLIKELY( -1==fstat( FD_BACKUP_POOL_FD( i ), &pool_st[ i ] ) ) )
      FD_LOG_ERR(( "fstat(snapshot pool fd %d) failed (%i-%s), was the snapshot pool initialized on boot?",
                   FD_BACKUP_POOL_FD( i ), errno, fd_io_strerror( errno ) ));
  }

  DIR * dir = opendir( snapshots_path );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", snapshots_path, errno, fd_io_strerror( errno ) ));

  struct dirent * entry;
  for(;;) {
    errno = 0;
    entry = readdir( dir );
    if( FD_UNLIKELY( !entry ) ) break;
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    struct stat st;
    if( FD_UNLIKELY( -1==fstatat( dirfd( dir ), entry->d_name, &st, 0 ) ) ) continue;

    for( uint i=0U; i<pool_cnt; i++ ) {
      if( FD_LIKELY( found[ i ] ) ) continue;
      if( FD_LIKELY( st.st_dev!=pool_st[ i ].st_dev || st.st_ino!=pool_st[ i ].st_ino ) ) continue;

      if( FD_UNLIKELY( strlen( entry->d_name )>=sizeof(slot[ i ].name) ) )
        FD_LOG_ERR(( "snapshot pool file name `%s` too long", entry->d_name ));
      fd_cstr_ncpy( slot[ i ].name, entry->d_name, sizeof(slot[ i ].name) );

      int is_zstd;
      uchar decoded_hash[ FD_HASH_FOOTPRINT ];
      if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &slot[ i ].full_slot, &slot[ i ].incr_slot, decoded_hash, &is_zstd ) ) ) {
        slot[ i ].full_slot = ULONG_MAX;
        slot[ i ].incr_slot = ULONG_MAX;
      }
      found[ i ] = 1;
      break;
    }
  }

  if( FD_UNLIKELY( errno ) ) FD_LOG_ERR(( "readdir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( uint i=0U; i<pool_cnt; i++ ) {
    if( FD_UNLIKELY( !found[ i ] ) )
      FD_LOG_ERR(( "snapshot pool fd %d has no directory entry in `%s`", FD_BACKUP_POOL_FD( i ), snapshots_path ));
  }
}
