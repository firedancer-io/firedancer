#include "fd_ssarchive.h"

#include "../../../util/fd_util.h"
#include "../../../app/platform/fd_file_util.h"

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#define FD_TEST_SSARCHIVE_NUM_SNAPSHOTS (3UL)

struct fd_test_ssarchive_env {
    char tmp_path[ PATH_MAX ];
    int dir_fd;
    int full_snapshot_fds[ FD_TEST_SSARCHIVE_NUM_SNAPSHOTS ];
    int incr_snapshot_fds[ FD_TEST_SSARCHIVE_NUM_SNAPSHOTS ];
};

typedef struct fd_test_ssarchive_env fd_test_ssarchive_env_t;

/* Two distinct valid base58 hashes, so that a test can tell which
   archive an out-param was copied from. */
#define HASH_A "AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM"
#define HASH_B "J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN"

static void
test_ssarchive_parse_filename( void ) {
  ulong full_slot;
  ulong incremental_slot;
  uchar hash[ FD_HASH_FOOTPRINT ];
  int   is_zstd;

  FD_TEST( fd_ssarchive_parse_filename( "snapshot-5-" HASH_A ".tar",
                                        &full_slot, &incremental_slot, hash, &is_zstd )==0 );
  FD_TEST( fd_ssarchive_parse_filename( "snapshot-+5-" HASH_A ".tar",
                                        &full_slot, &incremental_slot, hash, &is_zstd )==-1 );
  FD_TEST( fd_ssarchive_parse_filename( "snapshot-\t5-" HASH_A ".tar",
                                        &full_slot, &incremental_slot, hash, &is_zstd )==-1 );
  FD_TEST( fd_ssarchive_parse_filename( "incremental-snapshot-+5-6-" HASH_B ".tar.zst",
                                        &full_slot, &incremental_slot, hash, &is_zstd )==-1 );
  FD_TEST( fd_ssarchive_parse_filename( "incremental-snapshot-5-+6-" HASH_B ".tar.zst",
                                        &full_slot, &incremental_slot, hash, &is_zstd )==-1 );
  FD_TEST( fd_ssarchive_parse_filename( "incremental-snapshot-5-\t6-" HASH_B ".tar.zst",
                                        &full_slot, &incremental_slot, hash, &is_zstd )==-1 );
}

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
test_ssarchive_touch( fd_test_ssarchive_env_t * env,
                      int *                     out_fd,
                      char const *              name ) {
  int fd = openat( env->dir_fd, name, O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC, S_IRUSR|S_IWUSR );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "openat(%s/%s) failed (%i-%s)", env->tmp_path, name, errno, fd_io_strerror( errno ) ));
  *out_fd = fd;
}

/* decoded_hash avoids duplicating a base58 decoder in the tests. */

static void
decoded_hash( char const * name,
              uchar        out[ static FD_HASH_FOOTPRINT ] ) {
  ulong full_slot, incremental_slot;
  int   is_zstd;
  FD_TEST( fd_ssarchive_parse_filename( name, &full_slot, &incremental_slot, out, &is_zstd )==0 );
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
  FD_TEST( fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 1000UL, HASH_A ) );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 0UL ], full_snapshot_name );

  FD_TEST( fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 900UL, HASH_A ) );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 1UL ], full_snapshot_name );

  /* make some incremental snapshots */
  char incr_snapshot_name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", 1000UL, 1500UL, HASH_B ) );
  test_ssarchive_touch( &env, &env.incr_snapshot_fds[ 0UL ], incr_snapshot_name );

  FD_TEST( fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", 900UL, 1600UL, HASH_B ) );
  test_ssarchive_touch( &env, &env.incr_snapshot_fds[ 1UL ], incr_snapshot_name );

  ulong full_snapshot_slot;
  ulong incr_snapshot_slot;
  char full_path[ PATH_MAX ];
  char incr_path[ PATH_MAX ];
  int full_is_zstd;
  int incr_is_zstd;
  uchar full_snapshot_hash[ FD_HASH_FOOTPRINT ];
  uchar incr_snapshot_hash[ FD_HASH_FOOTPRINT ];
  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 1, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_snapshot_hash, incr_snapshot_hash )==0 );

  {
    FD_BASE58_ENCODE_32_BYTES( full_snapshot_hash, full_enc );
    FD_BASE58_ENCODE_32_BYTES( incr_snapshot_hash, incr_enc );
    FD_TEST( strcmp( full_enc, "AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM" )==0 );
    FD_TEST( strcmp( incr_enc, "J7FkN5APJtHepZGwd155s3V26TUHQ3r2Xu7UbX9y75mN" )==0 );
  }

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

  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 0, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_snapshot_hash, incr_snapshot_hash )==0 );

  {
    FD_BASE58_ENCODE_32_BYTES( full_snapshot_hash, full_enc );
    FD_TEST( strcmp( full_enc, "AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM" )==0 );
    uchar zero_hash[FD_HASH_FOOTPRINT] = {0};
    FD_TEST( memcmp( incr_snapshot_hash, zero_hash, FD_HASH_FOOTPRINT )==0 );
  }

  FD_TEST( full_snapshot_slot==1000UL );
  FD_TEST( incr_snapshot_slot==ULONG_MAX );
  FD_TEST( full_is_zstd==1 );
  FD_TEST( incr_is_zstd==0 );
  FD_TEST( fd_cstr_printf_check( expected_full_path, PATH_MAX, NULL, "%s/snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", env.tmp_path ) );
  FD_TEST( strlen(full_path)==strlen(expected_full_path) );
  FD_TEST( memcmp( full_path, expected_full_path, strlen(full_path) )==0 );
  FD_TEST( strcmp( incr_path, "" )==0 );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_pair_dangling_incr(void) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* make some full snapshots */
  char full_snapshot_name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 1000UL, HASH_A ) );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 0UL ], full_snapshot_name );

  FD_TEST( fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 500UL, HASH_A ) );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 1UL ], full_snapshot_name );

  /* make an incremental snapshot that doesn't build off any full snapshot */
  char incr_snapshot_name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( incr_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", 900UL, 1600UL, HASH_B ) );
  test_ssarchive_touch( &env, &env.incr_snapshot_fds[ 0UL ], incr_snapshot_name );

  ulong full_snapshot_slot;
  ulong incr_snapshot_slot;
  char full_path[ PATH_MAX ];
  char incr_path[ PATH_MAX ];
  int full_is_zstd;
  int incr_is_zstd;
  uchar full_snapshot_hash[ FD_HASH_FOOTPRINT ];
  uchar incr_snapshot_hash[ FD_HASH_FOOTPRINT ];
  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 1, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_snapshot_hash, incr_snapshot_hash )==0 );

  {
    FD_BASE58_ENCODE_32_BYTES( full_snapshot_hash, full_enc );
    FD_TEST( strcmp( full_enc, "AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM" )==0 );
    uchar zero_hash[FD_HASH_FOOTPRINT] = {0};
    FD_TEST( memcmp( incr_snapshot_hash, zero_hash, FD_HASH_FOOTPRINT )==0 );
  }

  FD_TEST( full_snapshot_slot==1000UL );
  FD_TEST( incr_snapshot_slot==ULONG_MAX );
  FD_TEST( full_is_zstd==1 );
  FD_TEST( incr_is_zstd==0 );
  char expected_full_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( expected_full_path, PATH_MAX, NULL, "%s/snapshot-1000-AGoNxxXQK4kCjeK4y8eJDaEfobS4QjMmCQm5zbEGq9kM.tar.zst", env.tmp_path ) );
  FD_TEST( strlen(full_path)==strlen(expected_full_path) );
  FD_TEST( memcmp( full_path, expected_full_path, strlen(full_path) )==0 );
  FD_TEST( strcmp( incr_path, "" )==0 );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_pair_no_incr( void ) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* Asking for a pair in a directory holding only full snapshots falls
     back to the latest full.  There is no incremental to report, so
     the path has to come back empty rather than untouched. */

  char full_snapshot_name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 1000UL, HASH_A ) );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 0UL ], full_snapshot_name );

  ulong full_snapshot_slot;
  ulong incr_snapshot_slot;
  char  full_path[ PATH_MAX ];
  char  incr_path[ PATH_MAX ];
  int   full_is_zstd;
  int   incr_is_zstd;
  uchar full_snapshot_hash[ FD_HASH_FOOTPRINT ];
  uchar incr_snapshot_hash[ FD_HASH_FOOTPRINT ];

  memset( incr_path, 'x', PATH_MAX );

  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 1, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_snapshot_hash, incr_snapshot_hash )==0 );

  FD_TEST( full_snapshot_slot==1000UL );
  FD_TEST( incr_snapshot_slot==ULONG_MAX );
  FD_TEST( strcmp( incr_path, "" )==0 );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_best( void ) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* full 900 pairs with incr 1600; full 2000 stands alone and reaches
     further */
  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 900UL, HASH_A ) );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 0UL ], name );

  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 2000UL, HASH_A ) );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 1UL ], name );

  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", 900UL, 1600UL, HASH_B ) );
  test_ssarchive_touch( &env, &env.incr_snapshot_fds[ 0UL ], name );

  ulong full_slot;
  ulong incr_slot;
  char  full_path[ PATH_MAX ];
  char  incr_path[ PATH_MAX ];
  int   full_is_zstd;
  int   incr_is_zstd;
  uchar full_hash[ FD_HASH_FOOTPRINT ];
  uchar incr_hash[ FD_HASH_FOOTPRINT ];

  /* incrementals enabled: the standalone full reaches 2000, the pair
     only 1600, so the full wins */
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 1, 0UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==ULONG_MAX );

  /* incrementals disabled and no target: full snapshots only */
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 0, 0UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==ULONG_MAX );

  /* incrementals disabled, target reachable by the full alone: the
     flag is honoured, the pair is not consulted */
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 0, 1500UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==ULONG_MAX );

  /* incrementals disabled, target beyond every candidate: the pair is
     consulted, but the full still reaches further */
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 0, 5000UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==ULONG_MAX );

  /* an incremental on top of the newest full now reaches furthest */
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", 2000UL, 2100UL, HASH_B ) );
  test_ssarchive_touch( &env, &env.incr_snapshot_fds[ 1UL ], name );

  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 1, 0UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==2100UL );

  /* still honoured with incrementals disabled and the target met */
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 0, 2000UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==ULONG_MAX );

  /* same target, incrementals enabled: the flag, not the target, is
     what admits the pair, so the incremental is taken even though the
     full already meets the target on its own */
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 1, 2000UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==2100UL );

  /* target the full cannot reach: the pair is consulted and wins */
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 0, 2050UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==2100UL );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_best_pair_replaces_full( void ) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* An older full carries the winning incremental, so the pair's full
     differs from the standalone pick in slot, path, hash and
     compression.  Every other pair-wins case has the two fulls
     coincide, leaving those four copies unobservable. */

  char full_a[ PATH_MAX ], full_b[ PATH_MAX ], incr[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( full_a, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 3000UL, HASH_A ) );
  FD_TEST( fd_cstr_printf_check( full_b, PATH_MAX, NULL, "snapshot-%lu-%s.tar",     2000UL, HASH_B ) );
  FD_TEST( fd_cstr_printf_check( incr,   PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", 2000UL, 3500UL, HASH_B ) );

  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 0UL ], full_a );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 1UL ], full_b );
  test_ssarchive_touch( &env, &env.incr_snapshot_fds[ 0UL ], incr   );

  ulong full_slot, incr_slot;
  char  full_path[ PATH_MAX ], incr_path[ PATH_MAX ];
  int   full_is_zstd, incr_is_zstd;
  uchar full_hash[ FD_HASH_FOOTPRINT ], incr_hash[ FD_HASH_FOOTPRINT ];

  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 1, 0UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==3500UL );

  /* The .tar full displaced the .tar.zst one. */
  FD_TEST( full_is_zstd==0 );
  FD_TEST( incr_is_zstd==1 );

  char expected_full[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( expected_full, PATH_MAX, NULL, "%s/%s", env.tmp_path, full_b ) );
  FD_TEST( !strcmp( full_path, expected_full ) );

  uchar expected_hash[ FD_HASH_FOOTPRINT ];
  decoded_hash( full_b, expected_hash );
  FD_TEST( !memcmp( full_hash, expected_hash, FD_HASH_FOOTPRINT ) );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_best_tie_keeps_full( void ) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* The pair reaches exactly as far as the standalone full.  The
     comparison is strict, so the full is kept and no incremental is
     loaded to arrive at the same slot. */

  char full_a[ PATH_MAX ], full_b[ PATH_MAX ], incr[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( full_a, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 2000UL, HASH_A ) );
  FD_TEST( fd_cstr_printf_check( full_b, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", 1000UL, HASH_B ) );
  FD_TEST( fd_cstr_printf_check( incr,   PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", 1000UL, 2000UL, HASH_B ) );

  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 0UL ], full_a );
  test_ssarchive_touch( &env, &env.full_snapshot_fds[ 1UL ], full_b );
  test_ssarchive_touch( &env, &env.incr_snapshot_fds[ 0UL ], incr   );

  ulong full_slot, incr_slot;
  char  full_path[ PATH_MAX ], incr_path[ PATH_MAX ];
  int   full_is_zstd, incr_is_zstd;
  uchar full_hash[ FD_HASH_FOOTPRINT ], incr_hash[ FD_HASH_FOOTPRINT ];

  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 1, 0UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==0 );
  FD_TEST( full_slot==2000UL );
  FD_TEST( incr_slot==ULONG_MAX );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_best_empty( void ) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  /* An empty directory has no full to pair with, so every combination
     of the flag and the target fails without reading the out-params. */

  ulong full_slot;
  ulong incr_slot;
  char  full_path[ PATH_MAX ];
  char  incr_path[ PATH_MAX ];
  int   full_is_zstd;
  int   incr_is_zstd;
  uchar full_hash[ FD_HASH_FOOTPRINT ];
  uchar incr_hash[ FD_HASH_FOOTPRINT ];

  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 0, 0UL,    &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==-1 );
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 1, 0UL,    &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==-1 );
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 0, 1000UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==-1 );
  FD_TEST( fd_ssarchive_latest_best( env.tmp_path, 1, 1000UL, &full_slot, &incr_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_hash, incr_hash )==-1 );

  test_ssarchive_fini( &env );
}

static void
test_ssarchive_latest_pair_over_capacity( void ) {
  fd_test_ssarchive_env_t env;
  test_ssarchive_init( &env );

  ulong const extra    = 17UL;
  ulong const snap_cnt = FD_SSARCHIVE_MAX_ENTRIES+extra;
  ulong const base     = 1000UL;
  for( ulong i=0UL; i<snap_cnt; i++ ) {
    char name[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL,
                                   "snapshot-%lu-%s.tar.zst", base+i, HASH_A ) );
    /* More archives than env has slots for, so close as we go. */
    int fd;
    test_ssarchive_touch( &env, &fd, name );
    if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  ulong full_snapshot_slot, incr_snapshot_slot;
  char  full_path[ PATH_MAX ], incr_path[ PATH_MAX ];
  int   full_is_zstd, incr_is_zstd;
  uchar full_snapshot_hash[ FD_HASH_FOOTPRINT ], incr_snapshot_hash[ FD_HASH_FOOTPRINT ];
  FD_TEST( fd_ssarchive_latest_pair( env.tmp_path, 0, &full_snapshot_slot, &incr_snapshot_slot, full_path, incr_path, &full_is_zstd, &incr_is_zstd, full_snapshot_hash, incr_snapshot_hash )==0 );
  FD_TEST( full_snapshot_slot==base+snap_cnt-1UL );
  FD_TEST( incr_snapshot_slot==ULONG_MAX );

  test_ssarchive_fini( &env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_ssarchive_parse_filename();
  test_ssarchive_latest_pair_basic();
  test_ssarchive_latest_pair_dangling_incr();
  test_ssarchive_latest_pair_no_incr();
  test_ssarchive_latest_best();
  test_ssarchive_latest_best_pair_replaces_full();
  test_ssarchive_latest_best_tie_keeps_full();
  test_ssarchive_latest_best_empty();
  test_ssarchive_latest_pair_over_capacity();
  return 0;
}
