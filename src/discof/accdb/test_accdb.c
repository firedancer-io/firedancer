#define _GNU_SOURCE

#include "fd_accdb.h"

#include <stdlib.h>
#include <sys/mman.h>

static uchar pubkey0[ 32UL ]  = { 0 };
static uchar pubkey1[ 32UL ]  = { 1, 0 };

uchar owner2[ 32UL ] = { 2, 0 };

void
test_basic( void ) {
  int fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  void * mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 1024UL, 64UL, 0UL ) );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( mem, 1024UL, 64UL, 0UL, 0UL ), fd );
  FD_TEST( accdb );

  ulong lamports;
  uchar data;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_initialize( accdb, 0UL );
  fd_accdb_attach_child( accdb, 1UL, 0UL );
  FD_TEST( !fd_accdb_read( accdb, 1UL, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !fd_accdb_read( accdb, 1UL, pubkey1, NULL, NULL, NULL, owner ) );
  fd_accdb_write( accdb, 1UL, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST( !fd_accdb_read( accdb, 1UL, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( fd_accdb_read( accdb, 1UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( lamports==1UL );
  FD_TEST( data_len==0UL );
  FD_TEST( !memcmp( owner, owner2, 32UL ) );
}

void
test_fork_basic( void ) {
  int fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  void * mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 1024UL, 64UL, 0UL ) );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( mem, 1024UL, 64UL, 0UL, 0UL ), fd );
  FD_TEST( accdb );

  ulong lamports;
  uchar data;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_initialize( accdb, 0UL );
  fd_accdb_attach_child( accdb, 1UL, 0UL );
  fd_accdb_attach_child( accdb, 2UL, 0UL );
  fd_accdb_attach_child( accdb, 3UL, 0UL );

  FD_TEST( !fd_accdb_read( accdb, 1UL, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !fd_accdb_read( accdb, 2UL, pubkey0, NULL, NULL, NULL, owner ) );
  FD_TEST( !fd_accdb_read( accdb, 3UL, pubkey0, NULL, NULL, NULL, owner ) );

  fd_accdb_write( accdb, 1UL, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST(  fd_accdb_read( accdb, 1UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( !fd_accdb_read( accdb, 2UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( !fd_accdb_read( accdb, 3UL, pubkey1, &lamports, &data, &data_len, owner ) );

  fd_accdb_write( accdb, 2UL, pubkey1, 1UL, NULL, 0UL, owner2 );
  FD_TEST(  fd_accdb_read( accdb, 1UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST(  fd_accdb_read( accdb, 2UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( !fd_accdb_read( accdb, 3UL, pubkey1, &lamports, &data, &data_len, owner ) );

  fd_accdb_attach_child( accdb, 4UL, 2UL );
  fd_accdb_attach_child( accdb, 5UL, 3UL );
  FD_TEST(  fd_accdb_read( accdb, 4UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( !fd_accdb_read( accdb, 5UL, pubkey1, &lamports, &data, &data_len, owner ) );
}

void
test_root_forks( void ) {
  int fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  void * mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 1024UL, 64UL, 0UL ) );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( mem, 1024UL, 64UL, 0UL, 0UL ), fd );
  FD_TEST( accdb );

  ulong lamports;
  uchar data;
  ulong data_len;
  uchar owner[ 32UL ];

  fd_accdb_initialize( accdb, 0UL );
  fd_accdb_attach_child( accdb, 1UL, 0UL );
  fd_accdb_attach_child( accdb, 2UL, 0UL );

  fd_accdb_write( accdb, 2UL, pubkey1, 1UL, NULL, 0UL, owner2 );
  fd_accdb_write( accdb, 1UL, pubkey1, 2UL, NULL, 0UL, owner2 );
  fd_accdb_attach_child( accdb, 3UL, 1UL );
  fd_accdb_write( accdb, 3UL, pubkey1, 3UL, NULL, 0UL, owner2 );
  FD_TEST( fd_accdb_read( accdb, 1UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( lamports==2UL );
  FD_TEST( fd_accdb_read( accdb, 2UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( lamports==1UL );
  FD_TEST( fd_accdb_read( accdb, 3UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( lamports==3UL );
  fd_accdb_root( accdb, 2UL );
  FD_TEST( !fd_accdb_read( accdb, 3UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( fd_accdb_read( accdb, 2UL, pubkey1, &lamports, &data, &data_len, owner ) );
  FD_TEST( lamports==1UL );
}

static uchar data[ 10UL*(1UL<<20) ];

void
test_compact( void ) {
  int fd = memfd_create( "accdb_test", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  void * mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 1024UL, 64UL, 0UL ) );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( mem, 1024UL, 64UL, 0UL, 0UL ), fd );
  FD_TEST( accdb );

  // ulong lamports;
  // uchar data;
  // ulong data_len;
  // uchar owner[ 32UL ];

  fd_accdb_initialize( accdb, 0UL );
  fd_accdb_attach_child( accdb, 1UL, 0UL );


  ulong writes_fit_in_partition = (1UL<<30UL)/(10UL*(1UL<<20UL)+80UL); // 1GiB partition, 10MiB account size + 80B overhead
  for( ulong i=0UL; i<writes_fit_in_partition; i++ ) {
    fd_accdb_write( accdb, 1UL, pubkey1, 1UL, data, 10UL*(1UL<<20UL), owner2 );
  }
  fd_accdb_metrics_t const * metrics = fd_accdb_metrics( accdb );
  FD_TEST( metrics->accounts_total           == 1UL );
  FD_TEST( metrics->accounts_capacity        == 1024UL );
  FD_TEST( metrics->bytes_read               == 0UL );
  FD_TEST( metrics->bytes_written            == writes_fit_in_partition*(10UL*(1UL<<20UL)+80UL) );
  FD_TEST( metrics->accounts_read            == 0UL );
  FD_TEST( metrics->accounts_written         == writes_fit_in_partition );
  FD_TEST( metrics->disk_allocated_bytes     == (1UL<<30UL) );
  FD_TEST( metrics->disk_used_bytes          == 1UL*(10UL*(1UL<<20UL)+80UL) );
  FD_TEST( metrics->in_compaction            == 0 );
  FD_TEST( metrics->compactions_requested    == 0UL );
  FD_TEST( metrics->compactions_completed    == 0UL );
  FD_TEST( metrics->accounts_relocated       == 0UL );
  FD_TEST( metrics->accounts_relocated_bytes == 0UL );
  FD_TEST( metrics->partitions_freed         == 0UL );

  fd_accdb_write( accdb, 1UL, pubkey1, 1UL, data, 10UL*(1UL<<20UL), owner2 );
  FD_TEST( metrics->in_compaction            == 1 );

  while( metrics->in_compaction ) {
    int charge_busy = 0;
    fd_accdb_compact( accdb, &charge_busy );
  }

  FD_TEST( metrics->accounts_total           == 1UL );
  FD_TEST( metrics->accounts_capacity        == 1024UL );
  FD_TEST( metrics->bytes_read               == writes_fit_in_partition*80UL );
  FD_TEST( metrics->bytes_written            == (writes_fit_in_partition+1UL)*(10UL*(1UL<<20UL)+80UL) );
  FD_TEST( metrics->accounts_read            == 0UL );
  FD_TEST( metrics->accounts_written         == 1UL+writes_fit_in_partition );
  FD_TEST( metrics->disk_allocated_bytes     == (2UL<<30UL) );
  FD_TEST( metrics->disk_used_bytes          == 1UL*(10UL*(1UL<<20UL)+80UL) );
  FD_TEST( metrics->in_compaction            == 0 );
  FD_TEST( metrics->compactions_requested    == 1UL );
  FD_TEST( metrics->compactions_completed    == 1UL );
  FD_TEST( metrics->accounts_relocated       == 0UL );
  FD_TEST( metrics->accounts_relocated_bytes == 0UL );
  FD_TEST( metrics->partitions_freed         == 1UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "test_basic ..." ));
  test_basic();

  FD_LOG_NOTICE(( "test_fork_basic ..." ));
  test_fork_basic();

  FD_LOG_NOTICE(( "test_root_forks ..." ));
  test_root_forks();

  FD_LOG_NOTICE(( "test_compact ..." ));
  test_compact();

  FD_LOG_NOTICE(( "success" ));
}
