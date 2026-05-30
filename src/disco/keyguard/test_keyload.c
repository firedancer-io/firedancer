#include "fd_keyload.h"

#include <setjmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_FORK_OK(child) do {                            \
    pid_t pid = fork();                                     \
    if( pid ) {                                             \
      int wstatus;                                          \
      FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) ); \
      FD_TEST( WIFEXITED( wstatus ) );                      \
      FD_TEST( !WEXITSTATUS( wstatus ) );                   \
      FD_TEST( !WIFSIGNALED( wstatus ) );                   \
      FD_TEST( !WIFSTOPPED( wstatus ) );                    \
    } else {                                                \
      do { child } while ( 0 );                             \
      exit( EXIT_SUCCESS );                                 \
    }                                                       \
} while( 0 )

void
test_protected_pages( void ) {
  pid_t pid = fork();
  if ( pid ) {
    int wstatus;
    FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );
    FD_TEST( WIFSIGNALED( wstatus ) && WTERMSIG( wstatus ) == SIGSEGV );
  } else { // child
    uchar * allocated = fd_keyload_alloc_protected_pages( 1UL, 1UL );
    /* This should trigger a segfault */
    uchar c = FD_VOLATILE_CONST( allocated[ 4096 ] );
    (void)c;
    exit( EXIT_FAILURE );
  }

  pid = fork();
  if( pid ) {
    int wstatus;
    FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );
    FD_TEST( WIFSIGNALED( wstatus ) && WTERMSIG( wstatus ) == SIGSEGV );
  } else { // child
    uchar * allocated = fd_keyload_alloc_protected_pages( 1UL, 1UL );
    /* This should trigger a segfault */
    uchar c = FD_VOLATILE_CONST( allocated[ -1 ] );
    (void)c;
    exit( EXIT_FAILURE );
  }

  uchar * allocated = fd_keyload_alloc_protected_pages( 1UL, 1UL );
  for( ulong i=0UL; i<4096UL; i++ ) FD_TEST( allocated[i]==0 );
  for( ulong i=0UL; i<4096UL; i++ ) allocated[i]=1;

  /* Wiped on fork */
  TEST_FORK_OK( for( ulong i=0UL; i<4096UL; i++ ) FD_TEST( allocated[i]==0 ); );
  /* But not in parent */
  for( ulong i=0UL; i<4096UL; i++ ) FD_TEST( allocated[i]==1 );
}

/* tmp_key_file creates a new (unprotected) key file with random bytes.
   tmp_key_file1 is a variant with chosen bytes.

   Returns a pointer to the cstr file path, which is valid until the
   next call to tmp_key_file or tmp_key_file1.

   The caller is responsible for deleting this file. */

static char const *
tmp_key_file1( uchar const content[ 64 ] ) {
  char json[ 512 ];
  char * p = fd_cstr_init( json );
  p = fd_cstr_append_char( p, '[' );
  for( ulong i=0UL; i<64UL; i++ ) {
    if( i ) p = fd_cstr_append_char( p, ',' );
    p = fd_cstr_append_uchar_as_text( p, 0, 0, (uchar)content[ i ], fd_uint_base10_dig_cnt( content[ i ] ) );
  }
  p = fd_cstr_append_char( p, ']' );
  ulong len = (ulong)( p-json );
  fd_cstr_fini( p );

  static char path[ 28 ];
  strcpy( path, "/tmp/fd_keyload_test_XXXXXX" );
  int fd = mkstemp( path );
  FILE * f = fdopen( fd, "wb" );
  FD_TEST( f );
  FD_TEST( fwrite( json, 1, len, f )==len );
  FD_TEST( !fclose( f ) );
  return path;
}

static char const *
tmp_key_file( void ) {
  uchar content[ 64 ];
  FD_TEST( fd_rng_secure( content, 32 ) );
  fd_sha512_t sha[1];
  fd_ed25519_public_from_private( content+32, content, sha );
  return tmp_key_file1( content );
}

static sigjmp_buf segv_jmpbuf;

static void
segfault_handler( int         signo,
                  siginfo_t * info,
                  void *      context ) {
  (void)signo; (void)info; (void)context;
  siglongjmp( segv_jmpbuf, 1 );
}

void
test_readonly( void ) {
  char const * path = tmp_key_file();
  uchar * key = (uchar *)fd_keyload_load( path, 0 );
  FD_TEST( key );
  FD_TEST( !unlink( path ) );

  struct sigaction sa = {0};
  sa.sa_sigaction = segfault_handler;
  sa.sa_flags     = SA_SIGINFO;
  FD_TEST( !sigaction( SIGSEGV, &sa, NULL ) );

  if( sigsetjmp( segv_jmpbuf, 0 )==0 ) {
    FD_VOLATILE( key[0] ) = 1;
    FD_COMPILER_MFENCE();
    FD_LOG_ERR(( "Write to readonly key page did not segfault" ));
  }

  FD_TEST( signal( SIGSEGV, SIG_DFL )!=SIG_ERR );
  fd_keyload_unload( key, 0 );
}

void
test_madvise( void ) {
  /* Query /proc/self/smaps to verify that madvise applied as intended

     smaps format is as follows:

     55555555a000-55555555c000 r--p 00006000 fd:01 537351138                  /usr/bin/bla
     Size:                  8 kB
     KernelPageSize:        4 kB
     MMUPageSize:           4 kB
     ...
     VmFlags: rd mr mw me sd */

  char const * path = tmp_key_file();
  uchar * key = fd_keyload_load( path, 0 );
  FD_TEST( key );
  FD_TEST( !unlink( path ) );

  FILE * maps = fopen( "/proc/self/smaps", "r" );
  FD_TEST( maps );
  char line[ 4096 ];

  /* Scan until we find a matching region */
  for(;;) {
    FD_TEST( fgets( line, sizeof(line), maps ) );
    ulong start, end;
    if( FD_UNLIKELY( sscanf( line, "%lx-%lx", &start, &end )!=2 ) ) continue;
    if( (void *)start==key ) break;
  }

  /* Now scan for VmFlags */
  struct {
    uint dd:1;
    uint wf:1;
  } flags = {0};
  for(;;) {
    FD_TEST( fgets( line, sizeof(line), maps ) );
    if( strncmp( line, "VmFlags: ", 9 )!=0 ) continue;
    char * tokens[ 16 ];
    ulong flag_cnt = fd_cstr_tokenize( tokens, 16, line+9, ' ' );
    for( ulong i=0UL; i<flag_cnt; i++ ) {
      if( strcmp( tokens[ i ], "dd" )==0 ) flags.dd = 1;
      if( strcmp( tokens[ i ], "wf" )==0 ) flags.wf = 1;
    }
    break;
  }
  if( FD_UNLIKELY( !flags.dd ) ) FD_LOG_ERR(( "key page missing MADV_DONTDUMP" ));
  if( FD_UNLIKELY( !flags.wf ) ) FD_LOG_ERR(( "key page missing MADV_WIPEONFORK" ));

  fd_keyload_unload( key, 0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_log_private_boot( &argc, &argv );
  test_protected_pages();
  test_readonly();
  test_madvise();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
