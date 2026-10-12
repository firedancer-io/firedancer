#include "../fd_util.h"
#include "fd_unit_test.c"
#include <sys/wait.h>
#include <unistd.h>

static uint seen;
static int reject;

FD_UNIT_TEST( alpha_0 ) {
  if( reject ) _exit( 2 );
  seen |= 1U;
}

FD_UNIT_TEST( beta_1 ) {
  if( reject ) _exit( 2 );
  seen |= 2U;
}

static void
test_args( int     expected_exit,
           uint    expected_mask,
           int     argc,
           char ** argv ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    seen = 0U;
    reject = !!expected_exit;
    fd_log_level_core_set( 5 );
    char * arg0 = argv[0];
    fd_unit_tests( argc, argv );
    _exit( seen==expected_mask && argv[0]==arg0 ? 0 : 2 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==expected_exit );
}

#define CHECK( exit_code, mask, ... ) do {                   \
  char * args[] = { __VA_ARGS__, NULL };                    \
  test_args( exit_code, mask, (int)(sizeof(args)/sizeof(char *)-1UL), args ); \
} while(0)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  char * empty_argv[1] = { NULL };
  test_args( 0, 3U, 0, empty_argv );
  CHECK( 0, 3U, "test" );
  CHECK( 0, 1U, "test", "alpha" );
  CHECK( 0, 3U, "test", "alpha", "beta" );
  CHECK( 0, 0U, "test", "absent" );
  CHECK( 0, 3U, "test", "--numa-idx", "0", "--page-cnt", "1", "--page-sz", "normal" );
  CHECK( 0, 3U, "test", "alpha", "--page-cnt", "-1", "beta", "--numa-idx", "+1",
         "--page-cnt", "0x1", "--page-sz", "4096", "--page-sz", "NORMAL" );
  CHECK( 1, 0U, "test", "--bogus", "alpha" );
  CHECK( 1, 0U, "test", "alpha", "--bogus" );
  CHECK( 1, 0U, "test", "--page-cnt", "1", "alpha", "--bogus" );
  char * opts[] = { "--numa-idx", "--page-cnt", "--page-sz" };
  for( ulong i=0UL; i<3UL; i++ ) {
    CHECK( 0, 3U, "test", opts[i], "" );
    CHECK( 0, 2U, "test", opts[i], "alpha_0", "beta" );
    CHECK( 1, 0U, "test", opts[i] );
    CHECK( 1, 0U, "test", "alpha", opts[i], "--bogus" );
    for( ulong j=0UL; j<3UL; j++ ) CHECK( 1, 0U, "test", opts[i], opts[j], "0" );
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
