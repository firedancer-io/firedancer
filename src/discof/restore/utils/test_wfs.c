#include "fd_wfs.h"
#include "../../../util/fd_util.h"

/* Stress-test the WFS classification spec (fd_wfs.h) in isolation,
   before any tile is refactored to use it.  The classifier is the single
   source of truth that snapct/snapin/gossip/replay must agree on, so the
   test enumerates every mode, every boundary, and the three boot
   scenarios from the stress-test report. */

#define S (100UL)       /* configured WFS slot            */
#define H_ZERO (1)      /* bank hash is all zeros (unset) */
#define H_SET  (0)      /* bank hash is set               */
#define SV (1234UL)     /* nonzero expected shred version */
#define UNK (ULONG_MAX) /* boot slot not yet known        */

static void
test_configured( void ) {
  /* All three required to enable WFS. */
  FD_TEST(  fd_wfs_configured( S, H_SET,  SV   ) );
  FD_TEST( !fd_wfs_configured( 0UL, H_SET,  SV ) ); /* slot 0 disables     */
  FD_TEST( !fd_wfs_configured( S, H_ZERO, SV   ) ); /* empty hash disables */
  FD_TEST( !fd_wfs_configured( S, H_SET,  0UL  ) ); /* shred version 0     */
  FD_TEST( !fd_wfs_configured( 0UL, H_ZERO, 0UL) ); /* nothing set         */
  FD_LOG_NOTICE(( "pass: test_configured" ));
}

static void
test_modes( void ) {
  /* DISABLED: any missing leg -> DISABLED regardless of boot slot. */
  FD_TEST( fd_wfs_mode( 0UL, H_SET,  SV,  UNK  )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( S,   H_ZERO, SV,  S    )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( S,   H_SET,  0UL, S    )==FD_WFS_MODE_DISABLED );

  /* UNRESOLVED: configured but boot slot unknown. */
  FD_TEST( fd_wfs_mode( S, H_SET, SV, UNK )==FD_WFS_MODE_UNRESOLVED );

  /* MATCH: configured, boot_slot==S.  Scenario 1 (coordinated restart). */
  FD_TEST( fd_wfs_mode( S, H_SET, SV, S )==FD_WFS_MODE_MATCH );

  /* NOOP: configured, boot_slot>S.  Scenario 2 (stale config, network
     moved on: fetched snapshot is ahead of S). */
  FD_TEST( fd_wfs_mode( S, H_SET, SV, S+1UL   )==FD_WFS_MODE_NOOP );
  FD_TEST( fd_wfs_mode( S, H_SET, SV, S+1000UL)==FD_WFS_MODE_NOOP );

  /* ERROR: configured, boot_slot<S (no snapshot bridged the gap). */
  FD_TEST( fd_wfs_mode( S, H_SET, SV, S-1UL )==FD_WFS_MODE_ERROR );
  FD_TEST( fd_wfs_mode( S, H_SET, SV, 0UL   )==FD_WFS_MODE_ERROR ); /* genesis boot */

  FD_LOG_NOTICE(( "pass: test_modes" ));
}

static void
test_boundaries( void ) {
  /* Exactly at S is MATCH; one slot either side flips mode.  This is the
     brittle exact-match hinge called out in the report. */
  FD_TEST( fd_wfs_mode( S, H_SET, SV, S-1UL )==FD_WFS_MODE_ERROR  );
  FD_TEST( fd_wfs_mode( S, H_SET, SV, S     )==FD_WFS_MODE_MATCH );
  FD_TEST( fd_wfs_mode( S, H_SET, SV, S+1UL )==FD_WFS_MODE_NOOP   );

  /* boot_slot is the effective slot after incremental application, not
     the full base slot.  A full at 90 + incremental at 100 boots at
     effective slot 100, which matches S=100 -> MATCH (not ERROR, as it
     would be if the base slot 90 were used). */
  FD_TEST( fd_wfs_mode( S, H_SET, SV, 100UL )==FD_WFS_MODE_MATCH );

  /* ULONG_MAX is reserved for "unknown", never treated as a real slot. */
  FD_TEST( fd_wfs_mode( S, H_SET, SV, UNK )==FD_WFS_MODE_UNRESOLVED );

  /* Scenario 3 (no WFS config): always DISABLED, whatever the boot slot. */
  FD_TEST( fd_wfs_mode( 0UL, H_ZERO, 0UL, UNK )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( 0UL, H_ZERO, 0UL, S   )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( 0UL, H_ZERO, 0UL, 0UL )==FD_WFS_MODE_DISABLED );

  FD_LOG_NOTICE(( "pass: test_boundaries" ));
}

static void
test_str( void ) {
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_DISABLED ), "disabled" ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_UNRESOLVED ), "unresolved" ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_MATCH    ), "match"    ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_NOOP     ), "no-op"    ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_ERROR    ), "error"    ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( 999 ),                  "unknown"  ) );
  FD_LOG_NOTICE(( "pass: test_str" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_configured();
  test_modes();
  test_boundaries();
  test_str();

  FD_LOG_NOTICE(( "pass: test_wfs" ));
  fd_halt();
  return 0;
}
