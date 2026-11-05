#include "../fd_util.h"
#include "fd_pcap.h"

#if FD_HAS_HOSTED

#include <stdio.h>

static void
test_pcap_iter_new( uint magic,
                    uint network,
                    int  type ) {
  uchar buf[ 64UL ];
  FILE * file = fmemopen( buf, sizeof(buf), "w+b" );
  FD_TEST( file );
  FD_TEST( fd_pcap_fwrite_hdr( file, network )==1UL );
  rewind( file );
  fd_memcpy( buf, &magic, sizeof(uint) );

  fd_pcap_iter_t * iter = fd_pcap_iter_new( file );
  FD_TEST( (!!iter)==(type>=0) );
  if( iter ) {
    FD_TEST( fd_pcap_iter_file( iter )==file );
    FD_TEST( fd_pcap_iter_type( iter )==(ulong)type );
    FD_TEST( ftell( file )==24L );
    FD_TEST( fd_pcap_iter_delete( iter )==file );
  }
  FD_TEST( fclose( file )==0 );
}

static void
test_pcap_network( void ) {
  static uint const magic[] = { 0xa1b2c3d4U, 0xa1b23c4dU };
  static uint const info[] = {
    0x00000000U, 0x04000000U, 0x14000000U, 0x24000000U,
    0x44000000U, 0xf4000000U, 0x20000000U, 0xf0000000U
  };
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
    { 0xffffU, -1 },
    { UINT_MAX, -1 }
  };

  for( ulong i=0UL; i<sizeof(magic)/sizeof(magic[0]); i++ ) {
    for( ulong j=0UL; j<sizeof(info)/sizeof(info[0]); j++ ) {
      for( ulong k=0UL; k<sizeof(cases)/sizeof(cases[0]); k++ ) {
        test_pcap_iter_new( magic[i], cases[k].network | info[j], cases[k].type );
      }
      for( uint bit=16U; bit<28U; bit++ ) {
        if( bit==26U ) continue;
        test_pcap_iter_new( magic[i], 1U   | info[j] | (1U<<bit), -1 );
        test_pcap_iter_new( magic[i], 113U | info[j] | (1U<<bit), -1 );
      }
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_pcap_network();

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
