#define _GNU_SOURCE
#include "fd_snap_pool.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

void
fd_snap_pool_recover( int                 snapshots_fd,
                      char const *        snapshots_path,
                      fd_backup_inode_t * pool,
                      uint                pool_max ) {
  FD_TEST( pool_max && pool_max<=FD_SNAP_MAX );

  struct stat pool_st[ FD_SNAP_MAX ];
  int         found  [ FD_SNAP_MAX ] = {0};
  for( uint i=0U; i<pool_max; i++ ) {
    if( FD_UNLIKELY( -1==fstat( FD_SNAP_FD( i ), &pool_st[ i ] ) ) )
      FD_LOG_ERR(( "fstat(snapshot pool fd %d) failed (%i-%s), was the snapshot pool initialized on boot?",
                   FD_SNAP_FD( i ), errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( lseek( snapshots_fd, 0L, SEEK_SET ) ) )
    FD_LOG_ERR(( "lseek(%s) failed (%i-%s)", snapshots_path, errno, fd_io_strerror( errno ) ));
  for(;;) {
    uchar buf[ 4096UL ] __attribute__((aligned(alignof(struct dirent))));
    long dents_sz = syscall( SYS_getdents64, snapshots_fd, buf, sizeof(buf) );
    if( FD_UNLIKELY( dents_sz<0L ) )
      FD_LOG_ERR(( "getdents64(%s) failed (%i-%s)", snapshots_path, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !dents_sz ) ) break;

    ulong off = 0UL;
    while( off<(ulong)dents_sz ) {
      struct dirent const * entry = (struct dirent const *)(buf+off);
      FD_TEST( entry->d_reclen && off+(ulong)entry->d_reclen<=(ulong)dents_sz );
      off += entry->d_reclen;
      if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

      struct stat st;
      if( FD_UNLIKELY( -1==fstatat( snapshots_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW ) ) ) continue;

      for( uint i=0U; i<pool_max; i++ ) {
        if( FD_LIKELY( found[ i ] ) ) continue;
        if( FD_LIKELY( st.st_dev!=pool_st[ i ].st_dev || st.st_ino!=pool_st[ i ].st_ino ) ) continue;

        if( FD_UNLIKELY( strlen( entry->d_name )>=sizeof(pool[ i ].name) ) )
          FD_LOG_ERR(( "snapshot pool file name `%s` too long", entry->d_name ));
        fd_cstr_ncpy( pool[ i ].name, entry->d_name, sizeof(pool[ i ].name) );

        int is_zstd;
        uchar decoded_hash[ FD_HASH_FOOTPRINT ];
        if( FD_UNLIKELY( -1==fd_ssarchive_parse_filename( entry->d_name, &pool[ i ].full_slot, &pool[ i ].incr_slot, decoded_hash, &is_zstd ) ) ) {
          pool[ i ].full_slot = ULONG_MAX;
          pool[ i ].incr_slot = ULONG_MAX;
        }
        found[ i ] = 1;
        break;
      }
    }
  }

  for( uint i=0U; i<pool_max; i++ ) {
    if( FD_UNLIKELY( !found[ i ] ) )
      FD_LOG_ERR(( "snapshot pool fd %d has no directory entry in `%s`", FD_SNAP_FD( i ), snapshots_path ));
  }
}
