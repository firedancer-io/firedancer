#include "../fd_util.h"
#include "fd_pcap.h"

#if FD_HAS_HOSTED

#include <stdio.h>

static void
test_pcap_iter_new( void ) {
  static uint const magic[] = { 0xa1b2c3d4U, 0xa1b23c4dU };
  static struct {
    uint network;
    int  type;
  } const cases[] = {
    {   1U, (int)FD_PCAP_ITER_TYPE_ETHERNET },
    { 113U, (int)FD_PCAP_ITER_TYPE_COOKED   },
    {   0U, -1 },
    {   2U, -1 },
    { 112U, -1 },
    { 114U, -1 },
    { 147U, -1 },
    { 276U, -1 },
    { UINT_MAX, -1 }
  };

  for( ulong i=0UL; i<sizeof(magic)/sizeof(magic[0]); i++ ) {
    for( ulong j=0UL; j<sizeof(cases)/sizeof(cases[0]); j++ ) {
      uchar buf[ 64UL ];
      FILE * file = fmemopen( buf, sizeof(buf), "w+b" );
      FD_TEST( file );
      FD_TEST( fd_pcap_fwrite_hdr( file, cases[j].network )==1UL );
      rewind( file );
      fd_memcpy( buf, magic+i, sizeof(uint) );

      fd_pcap_iter_t * iter = fd_pcap_iter_new( file );
      FD_TEST( (!!iter)==(cases[j].type>=0) );
      if( iter ) {
        FD_TEST( fd_pcap_iter_file( iter )==file );
        FD_TEST( fd_pcap_iter_type( iter )==(ulong)cases[j].type );
        FD_TEST( ftell( file )==24L );
        FD_TEST( fd_pcap_iter_delete( iter )==file );
      }
      FD_TEST( fclose( file )==0 );
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_pcap_iter_new();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "skip: unit test requires FD_HAS_HOSTED" ));
  fd_halt();
  return 0;
}

#endif
