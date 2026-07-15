#include "fd_event_os.h"
#include "../../util/fd_util.h"
#include "../../util/tmpl/fd_unit_test.c"

FD_UNIT_TEST( defaults ) {
  fd_event_os_release_t release[1];
  fd_event_os_release_parse( release, NULL, 0UL );
  FD_TEST( !strcmp( release->id, "linux" ) );
  FD_TEST( !strcmp( release->version_id, "" ) );
}

static void
test_release( char const * data,
              char const * expected_id,
              char const * expected_version_id ) {
  fd_event_os_release_t release[1];
  fd_event_os_release_parse( release, data, strlen( data ) );
  FD_TEST( !strcmp( release->id, expected_id ) );
  FD_TEST( !strcmp( release->version_id, expected_version_id ) );
}

FD_UNIT_TEST( distro_formats ) {
  test_release( "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nVERSION_ID=\"9.6\"\n",
                "rhel", "9.6" );
  test_release( "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"9.6\"\n",
                "rocky", "9.6" );
  test_release( "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
                "ubuntu", "24.04" );
  test_release( "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.21.3\n",
                "alpine", "3.21.3" );
}

FD_UNIT_TEST( normalization ) {
  test_release( "ID=UBUNTU\r\nVERSION_ID='24.04'\r\n", "ubuntu", "24.04" );
  test_release( "ID=rocky\nID=alpine\nVERSION_ID=3.20\nVERSION_ID=3.21\n",
                "alpine", "3.21" );
  test_release( "ID=not valid\nVERSION_ID=also/not/valid\n", "linux", "" );
  test_release( "ID=\"unterminated\nVERSION_ID=\n", "linux", "" );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
