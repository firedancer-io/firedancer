#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>

#include "../fd_util.h"
#include "../sanitize/fd_fuzz.h"
#include "fd_ip4.h"
#include "fd_ip6.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {

  /* Input must be a cstr */
  char * cstr = malloc( data_sz+1UL );
  FD_TEST( cstr );
  memcpy( cstr, data, data_sz );
  cstr[ data_sz ]='\0';

  char buf[ FD_IP6_ADDR_CSTR_MAX ];

  fd_ip6_addr_t addr;
  if( fd_cstr_to_ip6_addr( cstr, &addr ) ) {
    FD_FUZZ_MUST_BE_COVERED;

    FD_TEST( !addr.scope_id || fd_ip6_addr_is_scoped( addr.addr ) );
    fd_ip6_addr_cstr( buf, &addr );
    ulong len = strlen( buf );
    FD_TEST( len && len<FD_IP6_ADDR_CSTR_MAX );

    char host[ FD_IP6_ADDR_CSTR_MAX ];
    if( buf[ 0 ]=='[' ) { /* strip the brackets that URL hosts carry */
      FD_TEST( buf[ len-1UL ]==']' );
      memcpy( host, buf+1UL, len-2UL );
      host[ len-2UL ] = '\0';
    } else {
      memcpy( host, buf, len+1UL );
    }

    fd_ip6_addr_t addr2;
    FD_TEST( fd_cstr_to_ip46_addr( host, &addr2 ) );
    FD_TEST( fd_memeq( addr.addr, addr2.addr, 16UL ) );
    FD_TEST( addr.scope_id==addr2.scope_id );

    char buf2[ FD_IP6_ADDR_CSTR_MAX ];
    FD_TEST( !strcmp( fd_ip6_addr_cstr( buf2, &addr2 ), buf ) );
  }

  fd_ip6_addr_t addr46;
  if( fd_cstr_to_ip46_addr( cstr, &addr46 ) ) {
    FD_FUZZ_MUST_BE_COVERED;

    /* An IPv4 literal parses to the IPv4-mapped form of itself */
    uint ip4;
    if( fd_cstr_to_ip4_addr( cstr, &ip4 ) ) {
      FD_TEST( fd_ip6_addr_is_ip4_mapped( addr46.addr ) );
      FD_TEST( fd_ip6_addr_to_ip4( addr46.addr )==ip4 );
      FD_TEST( !addr46.scope_id );
    }

    (void)fd_ip6_addr_cstr( buf, &addr46 );
  }

  free( cstr );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
