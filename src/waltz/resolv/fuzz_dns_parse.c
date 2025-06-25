#include "../../util/fd_util.h"
#include "fd_lookup.h"
#include "fd_lookup_name.c"

#include <assert.h>
#include <stdlib.h>

int
LLVMFuzzerInitialize( int *argc,
                      char ***argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  (void) atexit( fd_halt );
  fd_log_level_core_set( 1 ); /* crash on info log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const *data,
                        ulong        size ) {
  /* Need at least one byte for rrtype selector and some payload. */
  if( size<2UL ) {
    return 0;
  }

  uint8_t rrtype = (data[ 0 ] & 1u) ? RR_A : RR_AAAA;

  struct address addrs[ MAXADDRS ] = {0};
  char           canon[ 256 ]      = {0};
  struct dpc_ctx ctx = {
      .addrs = addrs,
      .canon = canon,
      .cnt   = 0,
      .rrtype = rrtype,
  };

  fd_dns_parse( data+1, (int) (size-1UL), dns_parse_callback, &ctx );

  /* Basic post-conditions */
  FD_TEST( ctx.cnt>=0 );
  FD_TEST( ctx.cnt<=MAXADDRS );

  if( ctx.cnt>0 ) {
    int expected_family = fd_int_if( (rrtype==RR_A), AF_INET, AF_INET6  );
    FD_TEST( ctx.addrs[ 0 ].family==expected_family );
  }

  /* Canonical name, if set, must be a valid C string */
  if( canon[ 0 ] ) {
    FD_TEST( strlen( canon ) < sizeof(canon));
  }

  return 0;
}
