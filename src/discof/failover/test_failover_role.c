#define _GNU_SOURCE
#include "fd_failover_role.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uchar buf[ FD_FAILOVER_ROLE_FILE_SZ+64UL ];
static uchar demoted_buf[ FD_FAILOVER_DEMOTED_FILE_MAX ];

static fd_failover_role_file_t
sample( void ) {
  fd_failover_role_file_t role;
  fd_memset( &role, 0, sizeof(role) );
  role.version = FD_FAILOVER_ROLE_VERSION;
  role.term    = 42UL;
  role.role    = (uchar)FD_FAILOVER_STATE_ACTIVE;
  fd_memset( role.staked_pubkey, 0xAB, sizeof(role.staked_pubkey) );
  role.paused        = 1U;
  role.baton_slot    = 1234UL;
  role.engaged_floor = 1200UL;
  return role;
}

static void
refresh_digest( void ) {
  fd_sha256_hash( buf, FD_FAILOVER_ROLE_BODY_SZ, buf+FD_FAILOVER_ROLE_BODY_SZ );
}

static void
test_codec( void ) {
  fd_failover_role_file_t role = sample();
  ulong sz = fd_failover_role_ser( &role, buf );
  FD_TEST( sz==FD_FAILOVER_ROLE_FILE_SZ );
  FD_TEST( FD_LOAD( uint,  buf     )==FD_FAILOVER_ROLE_VERSION );
  FD_TEST( FD_LOAD( ulong, buf+4UL )==42UL );
  FD_TEST( buf[ 12UL ]==FD_FAILOVER_STATE_ACTIVE );

  fd_failover_role_file_t out;
  FD_TEST( !fd_failover_role_de( buf, sz, &out ) );
  FD_TEST( fd_memeq( &out, &role, sizeof(role) ) );
  FD_TEST( fd_failover_role_de( buf, sz-1UL, &out )==EPROTO );
  FD_TEST( !fd_failover_role_de( buf, sz+1UL, &out ) );
  FD_TEST( !fd_failover_role_de( buf, sz+64UL, &out ) );

  for( ulong i=0UL; i<sz; i++ ) {
    buf[ i ] ^= 1U;
    fd_memset( &out, 0x5A, sizeof(out) );
    fd_failover_role_file_t before = out;
    FD_TEST( fd_failover_role_de( buf, sz, &out )==EPROTO );
    FD_TEST( fd_memeq( &out, &before, sizeof(out) ) );
    buf[ i ] ^= 1U;
  }

  for( ulong i=0UL; i<sz; i++ )
    FD_TEST( fd_failover_role_de( buf, i, &out )==EPROTO );

  FD_STORE( uint, buf, 0U );
  refresh_digest();
  FD_TEST( fd_failover_role_de( buf, sz, &out )==EPROTO );
  FD_STORE( uint, buf, FD_FAILOVER_ROLE_VERSION+1U );
  refresh_digest();
  FD_TEST( fd_failover_role_de( buf, sz, &out )==EPROTO );

  sz = fd_failover_role_ser( &role, buf );
  buf[ 12UL ] = FD_FAILOVER_STATE_CNT;
  refresh_digest();
  FD_TEST( fd_failover_role_de( buf, sz, &out )==EPROTO );
  buf[ 12UL ] = role.role;
  buf[ 45UL ] = 2U;
  refresh_digest();
  FD_TEST( fd_failover_role_de( buf, sz, &out )==EPROTO );

  role.role = FD_FAILOVER_STATE_CNT;
  FD_TEST( !fd_failover_role_ser( &role, buf ) );
}

static void
test_storage( void ) {
  char dir_path[] = "/tmp/fd_failover_role.XXXXXX";
  FD_TEST( mkdtemp( dir_path ) );
  int dir_fd = open( dir_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  FD_TEST( dir_fd>=0 );
  int file_fd = fcntl( dir_fd, F_DUPFD_CLOEXEC, 0 );
  FD_TEST( file_fd>=0 );

  fd_failover_role_file_t role = sample();
  fd_failover_role_file_t out;
  FD_TEST( fd_failover_role_load( dir_fd, &out )==ENOENT );

  /* Sandboxed: the reserved descriptor is closed and openat must hand
     the same number back. */
  FD_TEST( !close( file_fd ) );
  FD_TEST( !fd_failover_role_store( dir_fd, file_fd, 1, UINT_MAX, UINT_MAX, &role ) );
  FD_TEST( fcntl( file_fd, F_GETFD )>=0 );
  FD_TEST( !fd_failover_role_load( dir_fd, &out ) );
  FD_TEST( fd_memeq( &out, &role, sizeof(role) ) );

  struct stat st;
  FD_TEST( !fstatat( dir_fd, FD_FAILOVER_ROLE_PATH, &st, AT_SYMLINK_NOFOLLOW ) );
  FD_TEST( S_ISREG( st.st_mode ) );
  FD_TEST( (st.st_mode & 0777)==0600 );

  int stale_fd = openat( dir_fd, FD_FAILOVER_ROLE_TMP_PATH, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600 );
  FD_TEST( stale_fd>=0 );
  FD_TEST( write( stale_fd, "stale", 5UL )==5L );
  FD_TEST( !close( stale_fd ) );
  role.term++;
  FD_TEST( !fd_failover_role_store( dir_fd, file_fd, 1, UINT_MAX, UINT_MAX, &role ) );
  FD_TEST( !fd_failover_role_load( dir_fd, &out ) );
  FD_TEST( out.term==role.term );

  /* Trailing bytes make it some other file, not this record. */
  int role_fd = openat( dir_fd, FD_FAILOVER_ROLE_PATH, O_WRONLY|O_APPEND|O_CLOEXEC );
  FD_TEST( role_fd>=0 );
  FD_TEST( write( role_fd, "trailing", 8UL )==8L );
  FD_TEST( !close( role_fd ) );
  FD_TEST( fd_failover_role_load( dir_fd, &out )==EPROTO );
  FD_TEST( !fd_failover_role_store( dir_fd, file_fd, 1, UINT_MAX, UINT_MAX, &role ) );
  FD_TEST( !fd_failover_role_load( dir_fd, &out ) );
  FD_TEST( fd_memeq( &out, &role, sizeof(role) ) );

  FD_TEST( !fchmodat( dir_fd, FD_FAILOVER_ROLE_PATH, 0644, 0 ) );
  FD_TEST( fd_failover_role_load( dir_fd, &out )==EACCES );
  FD_TEST( !fchmodat( dir_fd, FD_FAILOVER_ROLE_PATH, 0600, 0 ) );

  role_fd = openat( dir_fd, FD_FAILOVER_ROLE_PATH, O_WRONLY|O_CLOEXEC );
  FD_TEST( role_fd>=0 );
  uchar bad = 0xFFU;
  FD_TEST( pwrite( role_fd, &bad, 1UL, 4L )==1L );
  FD_TEST( !close( role_fd ) );
  FD_TEST( fd_failover_role_load( dir_fd, &out )==EPROTO );

  /* Unsandboxed: the reserved number stays open, so a lower descriptor
     is free and the new one is moved onto the reserved number. */
  role.term++;
  FD_TEST( !fd_failover_role_store( dir_fd, file_fd, 0, UINT_MAX, UINT_MAX, &role ) );
  FD_TEST( fcntl( file_fd, F_GETFD )>=0 );
  FD_TEST( !fd_failover_role_load( dir_fd, &out ) );
  FD_TEST( out.term==role.term );

  /* The write at boot is given the directory's owner, here our own user,
     and the file stays loadable. */
  role.term++;
  FD_TEST( !fd_failover_role_store( dir_fd, file_fd, 0, (uint)geteuid(), (uint)getegid(), &role ) );
  FD_TEST( !fstatat( dir_fd, FD_FAILOVER_ROLE_PATH, &st, AT_SYMLINK_NOFOLLOW ) );
  FD_TEST( st.st_uid==geteuid() && st.st_gid==getegid() );
  FD_TEST( !fd_failover_role_load( dir_fd, &out ) );
  FD_TEST( out.term==role.term );

  FD_TEST( !close( file_fd ) );
  FD_TEST( !unlinkat( dir_fd, FD_FAILOVER_ROLE_PATH, 0 ) );
  FD_TEST( !symlinkat( "/dev/null", dir_fd, FD_FAILOVER_ROLE_PATH ) );
  FD_TEST( fd_failover_role_load( dir_fd, &out )==ELOOP );
  FD_TEST( !unlinkat( dir_fd, FD_FAILOVER_ROLE_PATH, 0 ) );
  FD_TEST( !mkfifoat( dir_fd, FD_FAILOVER_ROLE_PATH, 0600 ) );
  alarm( 5U );
  FD_TEST( fd_failover_role_load( dir_fd, &out )==EACCES );
  alarm( 0U );
  FD_TEST( !unlinkat( dir_fd, FD_FAILOVER_ROLE_PATH, 0 ) );
  FD_TEST( !close( dir_fd ) );
  FD_TEST( !rmdir( dir_path ) );
}

static fd_failover_demoted_record_t
sample_demoted( void ) {
  fd_failover_demoted_record_t record;
  fd_memset( &record, 0, sizeof(record) );
  record.demoted.term           = 43UL;
  record.demoted.last_vote_slot = 900UL;
  record.demoted.watermark      = 17UL;
  record.demoted.mode           = (uchar)FD_FAILOVER_MODE_TOWER;
  record.demoted.state_len      = 5U;
  record.source                 = FD_FAILOVER_DEMOTED_SOURCE_PEER;
  fd_memcpy( record.state, "tower", 5UL );
  fd_sha256_hash( record.state, record.demoted.state_len, record.digest );
  return record;
}

static void
test_demoted_codec( void ) {
  fd_failover_demoted_record_t record = sample_demoted();
  ulong sz = fd_failover_demoted_ser( &record, demoted_buf );
  FD_TEST( sz==FD_FAILOVER_DEMOTED_FILE_BODY_MIN+record.demoted.state_len+32UL );

  fd_failover_demoted_record_t out;
  FD_TEST( !fd_failover_demoted_de( demoted_buf, sz, &out ) );
  FD_TEST( fd_memeq( &out, &record, sizeof(record) ) );

  /* The new source byte is protected by the file digest.  Version 1
     images still decode, with an explicitly unknown source. */
  FD_STORE( uint, demoted_buf, 1U );
  fd_sha256_hash( demoted_buf, sz-33UL, demoted_buf+sz-33UL );
  FD_TEST( !fd_failover_demoted_de( demoted_buf, sz-1UL, &out ) );
  FD_TEST( out.source==FD_FAILOVER_DEMOTED_SOURCE_UNKNOWN && out.demoted.term==record.demoted.term );
  sz = fd_failover_demoted_ser( &record, demoted_buf );
  record.source = 3U;
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
  record.source = FD_FAILOVER_DEMOTED_SOURCE_PEER;

  for( ulong i=0UL; i<sz; i++ ) {
    demoted_buf[ i ] ^= 1U;
    FD_TEST( fd_failover_demoted_de( demoted_buf, sz, &out )==EPROTO );
    demoted_buf[ i ] ^= 1U;
  }

  record.demoted.state_len = 0U;
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
  record = sample_demoted();
  record.demoted.term = ULONG_MAX-1UL;
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
  record = sample_demoted();
  record.demoted.mode = (uchar)FD_FAILOVER_MODE_CNT;
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
  record = sample_demoted();
  record.demoted.term = ULONG_MAX;
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
  record = sample_demoted();
  sz = fd_failover_demoted_ser( &record, demoted_buf );
  FD_STORE( ulong, demoted_buf+4UL, ULONG_MAX-1UL );
  fd_sha256_hash( demoted_buf, sz-32UL, demoted_buf+sz-32UL );
  FD_TEST( fd_failover_demoted_de( demoted_buf, sz, &out )==EPROTO );
  record = sample_demoted();
  sz = fd_failover_demoted_ser( &record, demoted_buf );
  FD_STORE( ulong, demoted_buf+4UL, ULONG_MAX );
  fd_sha256_hash( demoted_buf, sz-32UL, demoted_buf+sz-32UL );
  FD_TEST( fd_failover_demoted_de( demoted_buf, sz, &out )==EPROTO );
  record = sample_demoted();
  sz = fd_failover_demoted_ser( &record, demoted_buf );
  demoted_buf[ 4UL+3UL*sizeof(ulong) ] = (uchar)FD_FAILOVER_MODE_CNT;
  fd_sha256_hash( demoted_buf, sz-32UL, demoted_buf+sz-32UL );
  FD_TEST( fd_failover_demoted_de( demoted_buf, sz, &out )==EPROTO );
  record = sample_demoted();
  record.demoted.last_vote_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
}

static void
test_demoted_storage( void ) {
  char dir_path[] = "/tmp/fd_failover_demoted.XXXXXX";
  FD_TEST( mkdtemp( dir_path ) );
  int dir_fd = open( dir_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  FD_TEST( dir_fd>=0 );
  int file_fd = fcntl( dir_fd, F_DUPFD_CLOEXEC, 0 );
  FD_TEST( file_fd>=0 );

  fd_failover_demoted_record_t record = sample_demoted();
  fd_failover_demoted_record_t out;
  FD_TEST( fd_failover_demoted_load( dir_fd, &out )==ENOENT );
  FD_TEST( !fd_failover_demoted_store( dir_fd, file_fd, 1, UINT_MAX, UINT_MAX, &record ) );
  FD_TEST( !fd_failover_demoted_load( dir_fd, &out ) );
  FD_TEST( fd_memeq( &out, &record, sizeof(record) ) );

  record.demoted.term++;
  FD_TEST( !fd_failover_demoted_store( dir_fd, file_fd, 1, UINT_MAX, UINT_MAX, &record ) );
  FD_TEST( !fd_failover_demoted_load( dir_fd, &out ) );
  FD_TEST( out.demoted.term==record.demoted.term );

  FD_TEST( !close( file_fd ) );
  FD_TEST( !unlinkat( dir_fd, FD_FAILOVER_DEMOTED_PATH, 0 ) );
  FD_TEST( !mkfifoat( dir_fd, FD_FAILOVER_DEMOTED_PATH, 0600 ) );
  alarm( 5U );
  FD_TEST( fd_failover_demoted_load( dir_fd, &out )==EACCES );
  alarm( 0U );
  FD_TEST( !unlinkat( dir_fd, FD_FAILOVER_DEMOTED_PATH, 0 ) );
  FD_TEST( !close( dir_fd ) );
  FD_TEST( !rmdir( dir_path ) );
}

/* The same record in alpenglow mode with a history far past the tower
   limit.  The codec and the store never read the state, so the bytes
   only have to be reproducible. */
static fd_failover_demoted_record_t
sample_demoted_alpenglow( void ) {
  fd_failover_demoted_record_t record = sample_demoted();
  record.demoted.mode      = (uchar)FD_FAILOVER_MODE_ALPENGLOW;
  record.demoted.state_len = 5000U;
  for( ulong i=0UL; i<5000UL; i++ ) record.state[ i ] = (uchar)(i*7UL);
  fd_sha256_hash( record.state, record.demoted.state_len, record.digest );
  return record;
}

/* test_demoted_alpenglow: an alpenglow record with a 5000 byte state
   round-trips through the codec and the store, an unknown mode and a
   state past FD_FAILOVER_STATE_MAX are refused on both sides. */
static void
test_demoted_alpenglow( void ) {
  fd_failover_demoted_record_t record = sample_demoted_alpenglow();
  ulong sz = fd_failover_demoted_ser( &record, demoted_buf );
  FD_TEST( sz==FD_FAILOVER_DEMOTED_FILE_BODY_MIN+5000UL+32UL && sz<=FD_FAILOVER_DEMOTED_FILE_MAX );

  fd_failover_demoted_record_t out;
  FD_TEST( !fd_failover_demoted_de( demoted_buf, sz, &out ) );
  FD_TEST( fd_memeq( &out, &record, sizeof(record) ) );
  FD_TEST( out.demoted.mode==(uchar)FD_FAILOVER_MODE_ALPENGLOW && out.demoted.state_len==5000U );

  record.demoted.mode = (uchar)FD_FAILOVER_MODE_CNT;
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
  record = sample_demoted_alpenglow();
  sz = fd_failover_demoted_ser( &record, demoted_buf );
  demoted_buf[ 4UL+3UL*sizeof(ulong) ] = (uchar)FD_FAILOVER_MODE_CNT;
  fd_sha256_hash( demoted_buf, sz-32UL, demoted_buf+sz-32UL );
  FD_TEST( fd_failover_demoted_de( demoted_buf, sz, &out )==EPROTO );

  /* The length is checked before the body is sized from it. */
  record = sample_demoted_alpenglow();
  record.demoted.state_len = (ushort)(FD_FAILOVER_STATE_MAX+1UL);
  FD_TEST( !fd_failover_demoted_ser( &record, demoted_buf ) );
  record = sample_demoted_alpenglow();
  sz = fd_failover_demoted_ser( &record, demoted_buf );
  FD_STORE( ushort, demoted_buf+4UL+3UL*sizeof(ulong)+1UL, (ushort)(FD_FAILOVER_STATE_MAX+1UL) );
  fd_sha256_hash( demoted_buf, sz-32UL, demoted_buf+sz-32UL );
  FD_TEST( fd_failover_demoted_de( demoted_buf, sz, &out )==EPROTO );

  /* The file on disk comes back whole. */
  char dir_path[] = "/tmp/fd_failover_demoted_ag.XXXXXX";
  FD_TEST( mkdtemp( dir_path ) );
  int dir_fd = open( dir_path, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  FD_TEST( dir_fd>=0 );
  int file_fd = fcntl( dir_fd, F_DUPFD_CLOEXEC, 0 );
  FD_TEST( file_fd>=0 );
  record = sample_demoted_alpenglow();
  FD_TEST( !fd_failover_demoted_store( dir_fd, file_fd, 1, UINT_MAX, UINT_MAX, &record ) );
  FD_TEST( !fd_failover_demoted_load( dir_fd, &out ) );
  FD_TEST( fd_memeq( &out, &record, sizeof(record) ) );
  FD_TEST( !close( file_fd ) );
  FD_TEST( !unlinkat( dir_fd, FD_FAILOVER_DEMOTED_PATH, 0 ) );
  FD_TEST( !close( dir_fd ) );
  FD_TEST( !rmdir( dir_path ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_codec();
  test_storage();
  test_demoted_codec();
  test_demoted_storage();
  test_demoted_alpenglow();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
