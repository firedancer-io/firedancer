/* test_memguard plants memory corruption bugs and verifies that the
   FD_HAS_MEMGUARD instrumentation in fd_alloc detects each one (the
   detection path is FD_LOG_CRIT which aborts, so each planted bug runs
   in a forked child and the parent checks the child died).  Only built
   meaningfully with EXTRAS=memguard; without it the planted bugs go
   undetected and the test fails. */

#include "../fd_util.h"

#if FD_HAS_HOSTED && FD_HAS_MEMGUARD

#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>

static fd_wksp_t *  wksp;
static fd_alloc_t * alloc_join;

typedef void (*plant_t)( void );

static void
plant_overflow( void ) {
  uchar * p = fd_alloc_malloc( alloc_join, 16UL, 100UL );
  p[ 100 ] = 0xAA; /* one byte past the end */
  fd_alloc_free( alloc_join, p );
}

static void
plant_underflow( void ) {
  uchar * p = fd_alloc_malloc( alloc_join, 16UL, 100UL );
  p[ -1 ] ^= 0xFF; /* one byte before the start */
  fd_alloc_free( alloc_join, p );
}

static void
plant_double_free( void ) {
  uchar * p = fd_alloc_malloc( alloc_join, 16UL, 100UL );
  fd_alloc_free( alloc_join, p );
  fd_alloc_free( alloc_join, p );
}

static void
plant_write_after_free( void ) {
  uchar * p = fd_alloc_malloc( alloc_join, 16UL, 100UL );
  fd_alloc_free( alloc_join, p );
  p[ 50 ] = 0xAA;               /* write through dangling pointer */
  fd_alloc_is_empty( alloc_join ); /* flushes quarantine -> verifies */
}

static void
plant_wild_free( void ) {
  uchar * p = fd_alloc_malloc( alloc_join, 16UL, 100UL );
  fd_alloc_free( alloc_join, p+64UL ); /* interior pointer */
}

static int
expect_crit( char const * name,
             plant_t      plant ) {
  pid_t pid = fork();
  if( !pid ) {
    fd_log_level_logfile_set( 6 ); /* silence the child's CRIT spew */
    fd_log_level_stderr_set ( 6 );
    plant();
    exit( 0 ); /* bug not detected */
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  int detected = WIFSIGNALED( status ) || ( WIFEXITED( status ) && WEXITSTATUS( status )!=0 );
  FD_LOG_NOTICE(( "%-20s %s", name, detected ? "DETECTED" : "MISSED" ));
  return detected;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 32768UL, fd_log_cpu_id(), "memguard", 0U );
  FD_TEST( wksp );
  void * shmem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  alloc_join = fd_alloc_join( fd_alloc_new( shmem, 1UL ), 0UL );
  FD_TEST( alloc_join );

  /* Negative control: clean usage must not trip the detector */
  for( ulong i=0UL; i<1000UL; i++ ) {
    ulong sz = 1UL + (i*2654435761UL)%5000UL;
    uchar * p = fd_alloc_malloc( alloc_join, 16UL, sz );
    FD_TEST( p );
    fd_memset( p, 0x5A, sz );
    fd_alloc_free( alloc_join, p );
  }
  FD_TEST( fd_alloc_is_empty( alloc_join ) );
  FD_LOG_NOTICE(( "clean usage           OK" ));

  int ok = 1;
  ok &= expect_crit( "overflow",         plant_overflow         );
  ok &= expect_crit( "underflow",        plant_underflow        );
  ok &= expect_crit( "double free",      plant_double_free      );
  ok &= expect_crit( "write after free", plant_write_after_free );
  ok &= expect_crit( "wild free",        plant_wild_free        );
  FD_TEST( ok );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: requires FD_HAS_HOSTED and FD_HAS_MEMGUARD (EXTRAS=memguard)" ));
  fd_halt();
  return 0;
}

#endif
