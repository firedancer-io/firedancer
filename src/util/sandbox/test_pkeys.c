#define _GNU_SOURCE
#include "fd_pkeys.h"
#include "../fd_util.h"
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>

static sigjmp_buf test_sigsegv_jmp;
static volatile sig_atomic_t test_sigsegv_expected;
static volatile sig_atomic_t test_sigsegv_seen;

#define EXPECT_SIGSEGV( fail_msg, ... ) do {               \
    test_sigsegv_seen     = 0;                             \
    test_sigsegv_expected = 1;                             \
    test_sigsegv_trap();                                   \
    if( FD_LIKELY( !sigsetjmp( test_sigsegv_jmp, 1 ) ) ) { \
      __VA_ARGS__;                                         \
      test_sigsegv_expected = 0;                           \
      FD_LOG_CRIT(( fail_msg ));                           \
    }                                                      \
    test_sigsegv_expected = 0;                             \
    FD_TEST( test_sigsegv_seen );                          \
  } while(0)

static void
test_sigsegv_handler( int         sig,
                      siginfo_t * info,
                      void *      context ) {
  (void)info;
  (void)context;
  if( FD_LIKELY( sig==SIGSEGV && test_sigsegv_expected ) ) {
    test_sigsegv_seen = 1;
    siglongjmp( test_sigsegv_jmp, 1 );
  }

  raise( sig );
}

static void
test_sigsegv_trap( void ) {
  struct sigaction act[1];
  fd_memset( act, 0, sizeof(act) );
  act->sa_sigaction = test_sigsegv_handler;
  if( FD_UNLIKELY( sigemptyset( &act->sa_mask ) ) ) FD_LOG_ERR(( "sigemptyset failed" ));
  act->sa_flags = (int)(SA_SIGINFO | SA_RESETHAND);
  if( FD_UNLIKELY( sigaction( SIGSEGV, act, NULL ) ) ) FD_LOG_ERR(( "unable to override SIGSEGV" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_sigsegv_trap();

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  /* Test pkeys on writable workspace */

  ulong const page_sz  = FD_SHMEM_NORMAL_PAGE_SZ;
  ulong const page_cnt = 64UL;
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, cpu_idx, "test", 0UL );
  FD_TEST( wksp );

  ulong * word = fd_wksp_alloc_laddr( wksp, alignof(ulong), sizeof(ulong), 1UL );
  FD_TEST( word );

  FD_VOLATILE( *word ) = 0x42UL;
  FD_TEST( FD_VOLATILE_CONST( *word )==0x42UL );

  int pkey = fd_syscall_pkey_alloc( 0, 0 );
  if( FD_UNLIKELY( pkey<0 ) ) {
    FD_LOG_WARNING(( "pkey_alloc failed (%i-%s), skipping test", errno, fd_io_strerror( errno ) ));
    goto beach;
  }
  FD_LOG_NOTICE(( "pkey_alloc(0,0) = %i", pkey ));

  int err = fd_wksp_pkey_install( wksp, pkey );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_wksp_pkey_install failed (%i-%s)", err, fd_io_strerror( err ) ));

  FD_VOLATILE( *word ) = 0x42UL;
  FD_TEST( FD_VOLATILE_CONST( *word )==0x42UL );
  FD_LOG_NOTICE(( "pkey_install: pass" ));

  /* Drop write permissions */

  fd_x86_pkey_update( pkey, 0, 1 ); /* read only */
  FD_TEST( FD_VOLATILE_CONST( *word )==0x42UL );

  EXPECT_SIGSEGV( "write unexpectedly succeeded",
    FD_VOLATILE( *word ) = 0x43UL
  );
  FD_LOG_NOTICE(( "pkey read-only: pass" ));

  /* Drop access permissions */

  fd_x86_pkey_update( pkey, 1, 1 );

  EXPECT_SIGSEGV( "read unexpectedly succeeded",
    ulong x = FD_VOLATILE_CONST( *word );
    FD_COMPILER_FORGET( x )
  );

  EXPECT_SIGSEGV( "write unexpectedly succeeded",
    FD_VOLATILE( *word ) = 0x43UL
  );
  FD_LOG_NOTICE(( "pkey no access: pass" ));

  /* Restore full permissions */

  fd_x86_pkey_update( pkey, 0, 0 );
  FD_TEST( FD_VOLATILE_CONST( *word )==0x42UL );
  FD_VOLATILE( *word ) = 0x43UL;
  FD_TEST( FD_VOLATILE_CONST( *word )==0x43UL );

  /* Ensure that pkeys cannot raise permissions of a read-only mapping */

  fd_wksp_free_laddr( word );       word = NULL;
  fd_wksp_delete_anonymous( wksp ); wksp = NULL;
  FD_LOG_NOTICE(( "pkey_free(%d)", pkey ));
  FD_TEST( 0==fd_syscall_pkey_free( pkey ) ); pkey = -1;

  void * mem2 = mmap( NULL, page_sz, PROT_WRITE|PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0 );
  FD_TEST( mem2!=MAP_FAILED );
  wksp = fd_wksp_join( fd_wksp_new( mem2, "test2", 0, 2UL, fd_wksp_data_max_est( page_sz, 2UL ) ) );
  FD_TEST( wksp );
  word = fd_wksp_alloc_laddr( wksp, alignof(ulong), sizeof(ulong), 1UL );
  FD_TEST( word );
  FD_VOLATILE( *word ) = 0x1871UL;
  FD_TEST( 0==mprotect( mem2, page_sz, PROT_READ ) );
  FD_TEST( 0==fd_shmem_join_anonymous( "test2", FD_SHMEM_JOIN_MODE_READ_ONLY, wksp, mem2, page_sz, 1UL ) );
  pkey = fd_syscall_pkey_alloc( 0, 0 );
  if( FD_UNLIKELY( pkey<0 ) ) FD_LOG_ERR(( "pkey_alloc failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_LOG_NOTICE(( "pkey_alloc(0,0) = %i", pkey ) );
  fd_x86_pkey_update( pkey, 0, 0 ); /* full access */
  FD_TEST( 0==fd_wksp_pkey_install( wksp, pkey ) );

  FD_TEST( FD_VOLATILE_CONST( *word )==0x1871UL );
  EXPECT_SIGSEGV( "write unexpectedly succeeded",
    FD_VOLATILE( *word ) = 0x1933UL;
  );
  FD_LOG_NOTICE(( "pkey page ro / pkey full access: pass" ));

  word = NULL;
  FD_TEST( 0==fd_shmem_leave_anonymous( wksp, NULL ) );
  wksp = NULL;
  FD_TEST( 0==munmap( mem2, page_sz ) );
  FD_LOG_NOTICE(( "pkey_free(%d)", pkey ));
  FD_TEST( 0==fd_syscall_pkey_free( pkey ) ); pkey = -1;

beach:
  if( word ) fd_wksp_free_laddr( word );
  if( wksp ) fd_wksp_delete_anonymous( wksp );
  if( pkey>=0 ) FD_TEST( 0==fd_syscall_pkey_free( pkey ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
