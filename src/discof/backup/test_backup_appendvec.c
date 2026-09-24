/* Tests for the appendvec slot assignment used by the snapshot
   producer.  Agave rejects archives containing two appendvecs with
   the same slot, so every appendvec of an archive must get a distinct
   slot within the archive's slot window. */

#include "fd_backup.h"
#include "../../util/fd_util.h"

static void
test_full_slots( void ) {
  ulong const snap = 449759793UL;

  /* first appendvec sits at the snapshot slot, then count down */
  FD_TEST( fd_backup_appendvec_slot( snap, ULONG_MAX, 0UL )==snap     );
  FD_TEST( fd_backup_appendvec_slot( snap, ULONG_MAX, 1UL )==snap-1UL );
  FD_TEST( fd_backup_appendvec_slot( snap, ULONG_MAX, 15267UL )==snap-15267UL );

  /* slot 0 is a valid appendvec slot */
  FD_TEST( fd_backup_appendvec_slot( snap, ULONG_MAX, snap )==0UL );

  /* one past the window is rejected */
  FD_TEST( fd_backup_appendvec_slot( snap, ULONG_MAX, snap+1UL )==ULONG_MAX );

  /* tiny localnet snapshot slot */
  FD_TEST( fd_backup_appendvec_slot( 100UL, ULONG_MAX, 100UL )==0UL       );
  FD_TEST( fd_backup_appendvec_slot( 100UL, ULONG_MAX, 101UL )==ULONG_MAX );
}

static void
test_incremental_slots( void ) {
  ulong const base = 449759793UL;
  ulong const snap = base+200UL;

  /* first appendvec sits at the snapshot slot */
  FD_TEST( fd_backup_appendvec_slot( snap, base, 0UL )==snap );

  /* last valid appendvec sits just above the base slot */
  FD_TEST( fd_backup_appendvec_slot( snap, base, 199UL )==base+1UL );

  /* an appendvec at the base slot would collide with the full's first
     appendvec, so index 200 must be rejected */
  FD_TEST( fd_backup_appendvec_slot( snap, base, 200UL )==ULONG_MAX );
  FD_TEST( fd_backup_appendvec_slot( snap, base, 201UL )==ULONG_MAX );

  /* degenerate windows */
  FD_TEST( fd_backup_appendvec_slot( base,     base, 0UL )==ULONG_MAX ); /* empty window */
  FD_TEST( fd_backup_appendvec_slot( base-1UL, base, 0UL )==ULONG_MAX ); /* base above snapshot */
  FD_TEST( fd_backup_appendvec_slot( base+1UL, base, 0UL )==base+1UL  ); /* window of one */
  FD_TEST( fd_backup_appendvec_slot( base+1UL, base, 1UL )==ULONG_MAX );
}

static void
test_appendvec_name( void ) {
  char name[ FD_TAR_NAME_SZ ];

  FD_TEST( fd_backup_appendvec_name( name, 449759793UL )==name );
  FD_TEST( !strcmp( name, "accounts/449759793.0" ) );

  fd_backup_appendvec_name( name, 0UL );
  FD_TEST( !strcmp( name, "accounts/0.0" ) );

  fd_backup_appendvec_name( name, ULONG_MAX );
  FD_TEST( !strcmp( name, "accounts/18446744073709551615.0" ) );
  FD_TEST( strlen( name )<FD_TAR_NAME_SZ );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_full_slots();
  test_incremental_slots();
  test_appendvec_name();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
