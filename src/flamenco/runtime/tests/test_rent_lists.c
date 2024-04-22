#include "../fd_rent_lists.h"
#include "../../fd_flamenco.h"

void
test_partitions( ulong epoch_len ) {
  FD_TEST( epoch_len>0UL );
  ulong width = fd_rent_partition_width( epoch_len );
  FD_TEST( width>0UL );

  ulong last_key = ULONG_MAX;
  for( ulong i=0UL; i<epoch_len; i++ ) {
    ulong key1;
    ulong key0  = fd_rent_partition_to_key( i, width, epoch_len, &key1 );

    /* Ensure that keys spanned by partitions are contiguous and cover
       [0,2^64). */

    FD_TEST( key0 <= key1         );
    FD_TEST( last_key+1UL == key0 );
    last_key = key1;

    /* Ensure fd_rent_key_to_partition is the exact inverse of
       fd_rent_partition_to_key */

    FD_TEST( i==fd_rent_key_to_partition( key0, width, epoch_len )     );
    FD_TEST( i==fd_rent_key_to_partition( key1, width, epoch_len )     );
    FD_TEST( i!=fd_rent_key_to_partition( key0, width, epoch_len )-1UL );
    FD_TEST( i!=fd_rent_key_to_partition( key1, width, epoch_len )+1UL );
  }
  FD_TEST( last_key == ULONG_MAX );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  for( ulong n=5; n<19; n++ )
    test_partitions( 1UL<<n );
  test_partitions( 432000UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
