#include <stdio.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */
#include "fd_fib4_netlink.h"
#include "../../util/fd_util.h"

#define DEFAULT_FIB_SZ (1<<20) /* 1 MiB */

static uchar __attribute__((aligned(FD_FIB4_ALIGN)))
fib1_mem[ DEFAULT_FIB_SZ ];

/* Translate local and main tables and dump them to stdout */

void
dump_table( fd_netlink_t * netlink,
            uint           table ) {
  ulong const route_max = 256UL;
  FD_TEST( fd_fib4_footprint( route_max )<=sizeof(fib1_mem) );
  fd_fib4_t * fib = fd_fib4_join( fd_fib4_new( fib1_mem, route_max ) );

  int load_err = fd_fib4_netlink_load_table( fib, netlink, table );
  if( FD_UNLIKELY( load_err ) ) {
    FD_LOG_WARNING(( "Failed to load table %u (%i-%s)", table, load_err, fd_fib4_netlink_strerror( load_err ) ));
    return;
  }

  fprintf( stderr, "# ip route show table %u\n", table );
  fd_log_flush();
  fd_fib4_fprintf( fib, stderr );
  fputs( "\n", stderr );

  fd_fib4_delete( fd_fib4_leave( fib ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_netlink_t _netlink[1];
  fd_netlink_t * netlink = fd_netlink_init( _netlink, 42U );
  FD_TEST( netlink );

  FD_LOG_NOTICE(( "Dumping local and main routing tables to stderr\n" ));
  fd_log_flush();
  dump_table( netlink, RT_TABLE_LOCAL );
  dump_table( netlink, RT_TABLE_MAIN  );
  fflush( stderr );

  fd_netlink_fini( netlink );

  fd_halt();
  return 0;
}
