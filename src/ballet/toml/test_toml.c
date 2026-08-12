#include "fd_toml.h"
#include "../../util/fd_util.h"

#include <math.h>

/* parse_one parses a single-line TOML document of the form "x = <val>"
   and returns FD_TOML_SUCCESS on success.  The resulting pod is left in
   *pod for the caller to query. */

static int
parse_one( char const * toml,
           uchar *      pod ) {
  static uchar scratch[ 4096 ];
  return fd_toml_parse( toml, strlen( toml ), pod, scratch, sizeof(scratch), NULL );
}

static void
test_float_frac( void ) {
  uchar pod_mem[ 4096 ];

  static struct { char const * toml; float expected; } const cases[] = {
    { "x = 0.25",      0.25f      },
    { "x = 1.25",      1.25f      },
    { "x = 3.14",      3.14f      },
    { "x = 0.5",       0.5f       },
    { "x = 0.025",     0.025f     },
    { "x = 12.5",      12.5f      },
    { "x = 0.2_5",     0.25f      },
    { "x = 0.2_5_0",   0.250f     },
    { "x = 1.0",       1.0f       },
    { "x = 100.001",   100.001f   },
    { "x = 0.125e1",   1.25f      },
    { NULL, 0.0f }
  };

  for( ulong i=0UL; cases[i].toml; i++ ) {
    uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
    int err = parse_one( cases[i].toml, pod );
    FD_TEST( err==FD_TOML_SUCCESS );

    float got = fd_pod_query_float( pod, "x", NAN );
    float exp = cases[i].expected;
    float tol = fabsf( exp ) * 1e-5f + 1e-6f;
    if( FD_UNLIKELY( !isfinite( got ) || fabsf( got - exp ) > tol ) ) {
      FD_LOG_ERR(( "toml %s: got %.9g expected %.9g", cases[i].toml, (double)got, (double)exp ));
    }

    fd_pod_delete( fd_pod_leave( pod ) );
  }
}

static void
test_int_and_exp( void ) {
  uchar pod_mem[ 4096 ];

  {
    uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
    FD_TEST( parse_one( "x = 250", pod )==FD_TOML_SUCCESS );
    FD_TEST( fd_pod_query_long( pod, "x", 0L )==250L );
    fd_pod_delete( fd_pod_leave( pod ) );
  }

  {
    uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
    FD_TEST( parse_one( "x = 2_500", pod )==FD_TOML_SUCCESS );
    FD_TEST( fd_pod_query_long( pod, "x", 0L )==2500L );
    fd_pod_delete( fd_pod_leave( pod ) );
  }

  {
    uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
    FD_TEST( parse_one( "x = 2e3", pod )==FD_TOML_SUCCESS );
    float got = fd_pod_query_float( pod, "x", NAN );
    FD_TEST( fabsf( got - 2000.0f ) < 1e-2f );
    fd_pod_delete( fd_pod_leave( pod ) );
  }

  {
    uchar * pod = fd_pod_join( fd_pod_new( pod_mem, sizeof(pod_mem) ) );
    FD_TEST( parse_one( "x = 1.5e-2", pod )==FD_TOML_SUCCESS );
    float got = fd_pod_query_float( pod, "x", NAN );
    FD_TEST( fabsf( got - 0.015f ) < 1e-6f );
    fd_pod_delete( fd_pod_leave( pod ) );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_float_frac();
  test_int_and_exp();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
