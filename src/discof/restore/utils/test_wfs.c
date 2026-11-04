#include "fd_wfs.h"
#include "../../../util/fd_util.h"
#include "../../../ballet/base58/fd_base58.h"

/* Stress-test the WFS classification spec (fd_wfs.h) in isolation. */

#define S (100UL)       /* configured WFS slot            */
#define H_ZERO (1)      /* bank hash is all zeros (unset) */
#define H_SET  (0)      /* bank hash is set               */
#define V (1234UL)      /* nonzero expected shred version */
#define UNK (ULONG_MAX) /* boot slot not yet known        */

static void
test_configured( void ) {
  /* All three required to enable WFS. */
  FD_TEST(  fd_wfs_configured( S,   H_SET,  V   ) );
  FD_TEST( !fd_wfs_configured( 0UL, H_SET,  V   ) ); /* slot 0 disables     */
  FD_TEST( !fd_wfs_configured( S,   H_ZERO, V   ) ); /* empty hash disables */
  FD_TEST( !fd_wfs_configured( S,   H_SET,  0UL ) ); /* shred version 0     */
  FD_TEST( !fd_wfs_configured( 0UL, H_ZERO, 0UL ) ); /* nothing set         */
  FD_LOG_NOTICE(( "pass: test_configured" ));
}

static void
test_needs_incr( void ) {
  /* Without WFS the config flag decides on its own. */
  FD_TEST(  fd_wfs_needs_incr( 1, 0UL, H_ZERO, 0UL ) );
  FD_TEST( !fd_wfs_needs_incr( 0, 0UL, H_ZERO, 0UL ) );

  /* WFS forces it on, even against an explicit false. */
  FD_TEST(  fd_wfs_needs_incr( 0, S, H_SET, V ) );
  FD_TEST(  fd_wfs_needs_incr( 1, S, H_SET, V ) );

  /* A partial triple is not WFS, so it forces nothing. */
  FD_TEST( !fd_wfs_needs_incr( 0, 0UL, H_SET,  V   ) );
  FD_TEST( !fd_wfs_needs_incr( 0, S,   H_ZERO, V   ) );
  FD_TEST( !fd_wfs_needs_incr( 0, S,   H_SET,  0UL ) );

  FD_LOG_NOTICE(( "pass: test_needs_incr" ));
}

static void
test_modes( void ) {
  /* DISABLED: any missing leg -> DISABLED regardless of boot slot. */
  FD_TEST( fd_wfs_mode( 0UL, H_SET,  V,   UNK )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( S,   H_ZERO, V,   S   )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( S,   H_SET,  0UL, S   )==FD_WFS_MODE_DISABLED );

  /* UNRESOLVED: configured but boot slot unknown. */
  FD_TEST( fd_wfs_mode( S, H_SET, V, UNK )==FD_WFS_MODE_UNRESOLVED );

  /* MATCH: configured, boot_slot==S.  Scenario 1 (coordinated restart). */
  FD_TEST( fd_wfs_mode( S, H_SET, V, S )==FD_WFS_MODE_MATCH );

  /* NOOP: configured, boot_slot>S.  Scenario 2 (stale config, network
     moved on: fetched snapshot is ahead of S). */
  FD_TEST( fd_wfs_mode( S, H_SET, V, S+1UL    )==FD_WFS_MODE_NOOP );
  FD_TEST( fd_wfs_mode( S, H_SET, V, S+1000UL )==FD_WFS_MODE_NOOP );

  /* ERROR: configured, boot_slot<S (no snapshot bridged the gap). */
  FD_TEST( fd_wfs_mode( S, H_SET, V, S-1UL )==FD_WFS_MODE_ERROR );
  FD_TEST( fd_wfs_mode( S, H_SET, V, 0UL   )==FD_WFS_MODE_ERROR ); /* genesis boot */

  FD_LOG_NOTICE(( "pass: test_modes" ));
}

static void
test_boundaries( void ) {
  /* Exactly at S is MATCH; one slot either side flips mode.  boot_slot
     is the effective slot, not the full's base slot: a full at 90 with
     an incremental at 100 is MATCH, the base slot 90 would be ERROR. */
  FD_TEST( fd_wfs_mode( S, H_SET, V, S-1UL )==FD_WFS_MODE_ERROR );
  FD_TEST( fd_wfs_mode( S, H_SET, V, S     )==FD_WFS_MODE_MATCH );
  FD_TEST( fd_wfs_mode( S, H_SET, V, S+1UL )==FD_WFS_MODE_NOOP  );

  /* ULONG_MAX is reserved for "unknown", never treated as a real slot.
     It outranks every other check, so even S==ULONG_MAX (which would
     otherwise look like a MATCH) resolves to UNRESOLVED.  Nothing
     validates S against the sentinel, so this ordering is what keeps
     an absurd config from silently passing as a matched restart. */
  FD_TEST( fd_wfs_mode( S,   H_SET, V, UNK )==FD_WFS_MODE_UNRESOLVED );
  FD_TEST( fd_wfs_mode( UNK, H_SET, V, UNK )==FD_WFS_MODE_UNRESOLVED );

  /* One below the sentinel is an ordinary slot. */
  FD_TEST( fd_wfs_mode( S,       H_SET, V, UNK-1UL )==FD_WFS_MODE_NOOP  );
  FD_TEST( fd_wfs_mode( UNK-1UL, H_SET, V, UNK-1UL )==FD_WFS_MODE_MATCH );
  FD_TEST( fd_wfs_mode( UNK,     H_SET, V, UNK-1UL )==FD_WFS_MODE_ERROR );

  /* S==0 disables WFS outright, so boot_slot 0 is DISABLED and not the
     MATCH that a naive boot_slot==slot comparison would give. */
  FD_TEST( fd_wfs_mode( 0UL, H_SET, V, 0UL )==FD_WFS_MODE_DISABLED );

  /* Scenario 3 (no WFS config): always DISABLED, whatever the boot slot. */
  FD_TEST( fd_wfs_mode( 0UL, H_ZERO, 0UL, UNK )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( 0UL, H_ZERO, 0UL, S   )==FD_WFS_MODE_DISABLED );
  FD_TEST( fd_wfs_mode( 0UL, H_ZERO, 0UL, 0UL )==FD_WFS_MODE_DISABLED );

  FD_LOG_NOTICE(( "pass: test_boundaries" ));
}

static void
test_all_zeros_bank_hash( void ) {
  /* hash_is_zero is derived from the config string in topology.c and
     from the decoded bytes in the tiles (fd_wfs.h). */
  uchar out[ 32 ];

  char const * canonical = "11111111111111111111111111111111"; /* 32 */
  FD_TEST( fd_base58_decode_32( canonical, out ) );
  FD_TEST( fd_memeq( out, (uchar[32]){0}, 32UL ) );

  /* Any other run of '1's decodes to a different byte count, so no
     second spelling of the all-zeros hash reaches the tiles. */
  FD_TEST( !fd_base58_decode_32( "",                                  out ) );
  FD_TEST( !fd_base58_decode_32( "1",                                 out ) );
  FD_TEST( !fd_base58_decode_32( "1111111111111111111111111111111",   out ) ); /* 31 */
  FD_TEST( !fd_base58_decode_32( "111111111111111111111111111111111", out ) ); /* 33 */

  FD_LOG_NOTICE(( "pass: test_all_zeros_bank_hash" ));
}

static void
test_str( void ) {
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_DISABLED   ), "disabled"   ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_UNRESOLVED ), "unresolved" ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_MATCH      ), "match"      ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_NOOP       ), "no-op"      ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( FD_WFS_MODE_ERROR      ), "error"      ) );
  FD_TEST( !strcmp( fd_wfs_mode_str( 999 ),                    "unknown"    ) );
  FD_LOG_NOTICE(( "pass: test_str" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_configured();
  test_needs_incr();
  test_modes();
  test_boundaries();
  test_all_zeros_bank_hash();
  test_str();

  FD_LOG_NOTICE(( "pass: test_wfs" ));
  fd_halt();
  return 0;
}
