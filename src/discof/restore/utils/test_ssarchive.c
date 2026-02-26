#include "fd_ssarchive.h"

#include "../../../util/fd_util.h"
#include "../../../app/platform/fd_file_util.h"

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define FD_TEST_SSARCHIVE_NUM_SNAPSHOTS (3UL)

struct fd_test_ssarchive_env {
    char tmp_path[ PATH_MAX ];
    int dir_fd;
    int full_snapshot_fds[ FD_TEST_SSARCHIVE_NUM_SNAPSHOTS ];
    int incr_snapshot_fds[ FD_TEST_SSARCHIVE_NUM_SNAPSHOTS ];
};

typedef struct fd_test_ssarchive_env fd_test_ssarchive_env_t;

static void
test_ssarchive_init(fd_test_ssarchive_env_t * env) {
  char tmp_path_template[] = "/tmp/test_ssarchive.XXXXXX";
  char * tmp_path          = mkdtemp(tmp_path_template);
  if( FD_UNLIKELY( !tmp_path ) ) FD_LOG_ERR(( "mkdtemp(%s) failed (%i-%s)", tmp_path_template, errno, fd_io_strerror( errno )));
  fd_memcpy( env->tmp_path, tmp_path, sizeof(tmp_path_template) );

  env->dir_fd = open( tmp_path, O_DIRECTORY|O_CLOEXEC );
  if( env->dir_fd == -1 ) FD_LOG_ERR(("open(%s) failed (%i-%s)", tmp_path, errno, fd_io_strerror( errno )));

  for( ulong i=0UL; i<FD_TEST_SSARCHIVE_NUM_SNAPSHOTS; i++ ) {
    env->full_snapshot_fds[ i ] = -1;
    env->incr_snapshot_fds[ i ] = -1;
  }
}

static void
test_ssarchive_fini( fd_test_ssarchive_env_t * env ) {
  if( close( env->dir_fd ) ) FD_LOG_ERR(("close() failed (%i-%s)", errno, fd_io_strerror( errno )));

  for( ulong i=0UL; i<FD_TEST_SSARCHIVE_NUM_SNAPSHOTS; i++ ) {
    if( env->full_snapshot_fds[ i ]!=-1 ) {
      if( close( env->full_snapshot_fds[ i ] ) ) FD_LOG_ERR(("close() failed (%i-%s)", errno, fd_io_strerror( errno )));
    }
    if( env->incr_snapshot_fds[ i ]!=-1 ) {
      if( close( env->incr_snapshot_fds[ i ] ) ) FD_LOG_ERR(("close() failed (%i-%s)", errno, fd_io_strerror( errno )));
    }
  }

  if( FD_UNLIKELY( fd_file_util_rmtree( env->tmp_path, 1 ) ) ) FD_LOG_ERR(("fd_file_util_rmtree(%s) failed (%i-%s)", env->tmp_path, errno, fd_io_strerror( errno )));
}

static void
test_ssarchive_latest_pair_basic(void) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* make some full snapshots */
  char full_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", 1000UL );
  env.full_snapshot_fds[ 0UL ] = openat( env.dir_fd, full_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.full_snapshot_fds[ 0UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", full_snapshot_name, errno, fd_io_strerror( errno )));

  fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", 900UL );
  env.full_snapshot_fds[ 1UL ] = openat( env.dir_fd, full_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.full_snapshot_fds[ 1UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", full_snapshot_name, errno, fd_io_strerror( errno )));

  /* make some incremental snapshots */
  char incr_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst", 1000UL, 1500UL );
  env.incr_snapshot_fds[ 0UL ] = openat( env.dir_fd, incr_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.incr_snapshot_fds[ 0UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", incr_snapshot_name, errno, fd_io_strerror( errno )));

  fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst", 900UL, 1600UL );
  env.incr_snapshot_fds[ 1UL ] = openat( env.dir_fd, incr_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.incr_snapshot_fds[ 1UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", incr_snapshot_name, errno, fd_io_strerror( errno )));

  ulong full_snapshot_slot;
  ulong incr_snapshot_slot;
  char full_path[ PATH_MAX ];
  char incr_path[ PATH_MAX ];
  int full_is_zstd;
  int incr_is_zstd;
  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 1, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd )==0 );

  FD_TEST( full_snapshot_slot==900UL );
  FD_TEST( incr_snapshot_slot==1600UL );
  FD_TEST( full_is_zstd==1 );
  FD_TEST( incr_is_zstd==1 );
  char expected_full_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( expected_full_path, PATH_MAX, NULL, "%s/snapshot-900-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", env.tmp_path ) );
  FD_TEST( strlen(full_path)==strlen(expected_full_path) );
  FD_TEST( memcmp( full_path, expected_full_path, strlen(full_path) )==0 );
  char expected_incr_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( expected_incr_path, PATH_MAX, NULL, "%s/incremental-snapshot-900-1600-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst", env.tmp_path ) );
  FD_TEST( strlen(incr_path)==strlen(expected_incr_path) );
  FD_TEST( memcmp( incr_path, expected_incr_path, strlen(incr_path) )==0 );

  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 0, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd )==0 );

  FD_TEST( full_snapshot_slot==1000UL );
  FD_TEST( incr_snapshot_slot==ULONG_MAX );
  FD_TEST( full_is_zstd==1 );
  FD_TEST( incr_is_zstd==0 );
  FD_TEST( fd_cstr_printf_check( expected_full_path, PATH_MAX, NULL, "%s/snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", env.tmp_path ) );
  FD_TEST( strlen(full_path)==strlen(expected_full_path) );
  FD_TEST( memcmp( full_path, expected_full_path, strlen(full_path) )==0 );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_pair_dangling_incr(void) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* make some full snapshots */
  char full_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", 1000UL );
  env.full_snapshot_fds[ 0UL ] = openat( env.dir_fd, full_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.full_snapshot_fds[ 0UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", full_snapshot_name, errno, fd_io_strerror( errno )));

  fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", 500UL );
  env.full_snapshot_fds[ 1UL ] = openat( env.dir_fd, full_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.full_snapshot_fds[ 1UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", full_snapshot_name, errno, fd_io_strerror( errno )));

  /* make an incremental snapshot that doesn't build off any full snapshot */
  char incr_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst", 900UL, 1600UL );
  env.incr_snapshot_fds[ 0UL ] = openat( env.dir_fd, incr_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.incr_snapshot_fds[ 0UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", incr_snapshot_name, errno, fd_io_strerror( errno )));

  ulong full_snapshot_slot;
  ulong incr_snapshot_slot;
  char full_path[ PATH_MAX ];
  char incr_path[ PATH_MAX ];
  int full_is_zstd;
  int incr_is_zstd;
  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 1, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd )==0 );

  FD_TEST( full_snapshot_slot==1000UL );
  FD_TEST( incr_snapshot_slot==ULONG_MAX );
  FD_TEST( full_is_zstd==1 );
  FD_TEST( incr_is_zstd==0 );
  char expected_full_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( expected_full_path, PATH_MAX, NULL, "%s/snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", env.tmp_path ) );
  FD_TEST( strlen(full_path)==strlen(expected_full_path) );
  FD_TEST( memcmp( full_path, expected_full_path, strlen(full_path) )==0 );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_remove_old_snapshots(void) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  char full_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", 1000UL );
  env.full_snapshot_fds[ 0UL ] = openat( env.dir_fd, full_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.full_snapshot_fds[ 0UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", full_snapshot_name, errno, fd_io_strerror( errno )));

  /* this full snapshot should be kept because its corresponding
     incremental snapshot has the highest slot. */
  fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", 900UL );
  env.full_snapshot_fds[ 1UL ] = openat( env.dir_fd, full_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.full_snapshot_fds[ 1UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", full_snapshot_name, errno, fd_io_strerror( errno )));

  /* make some incremental snapshots */
  char incr_snapshot_name[ PATH_MAX ];
  fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst", 1000UL, 1500UL );
  env.incr_snapshot_fds[ 0UL ] = openat( env.dir_fd, incr_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.incr_snapshot_fds[ 0UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", incr_snapshot_name, errno, fd_io_strerror( errno )));

  fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst", 900UL, 1600UL );
  env.incr_snapshot_fds[ 1UL ] = openat( env.dir_fd, incr_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.incr_snapshot_fds[ 1UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", incr_snapshot_name, errno, fd_io_strerror( errno )));

  /* this snapshot should be deleted because even though its slot is the
     highest, there is no corresponding full snapshot. */
  fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst", 1100UL, 1700UL );
  env.incr_snapshot_fds[ 2UL ] = openat( env.dir_fd, incr_snapshot_name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( env.incr_snapshot_fds[ 2UL ] == -1 ) FD_LOG_ERR(("openat(%s) failed (%i-%s)", incr_snapshot_name, errno, fd_io_strerror( errno )));

  fd_ssarchive_remove_old_snapshots( env.tmp_path, 1, 1 );

   /* after removing old snapshots, only the full snapshot with slot 900
      and the incremental snapshot with slot 1600 should remain. */
  DIR * dir = opendir( env.tmp_path );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return;
    FD_LOG_ERR(( "opendir() failed `%s` (%i-%s)", env.tmp_path, errno, fd_io_strerror( errno ) ));
  }

  struct dirent * entry;
  errno = 0;
  while(( entry = readdir( dir ) )) {
    if( FD_LIKELY( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) ) ) continue;

    if(!strcmp(entry->d_name, "snapshot-900-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst" ) ) continue;
    if( !strcmp( entry->d_name, "incremental-snapshot-900-1600-J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN.tar.zst" ) ) continue;

    FD_LOG_ERR(( "unexpected file `%s/%s` after removing old snapshots", env.tmp_path, entry->d_name ));
  }

  test_ssarchive_fini( &env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_ssarchive_latest_pair_basic();
  test_ssarchive_latest_pair_dangling_incr();
  test_ssarchive_remove_old_snapshots();
  return 0;
}
