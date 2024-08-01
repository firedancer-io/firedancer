#include "fd_keyload.h"

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#define TEST_FORK_OK(child) do {                            \
    pid_t pid = fork();                                     \
    FD_TEST( pid!=-1 );                                     \
    if ( pid ) {                                            \
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
  if ( pid ) {
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

/* write_key_file writes keypair in JSON key file format to key_fd,
   then closes key_fd. */

static void
write_key_file( int         key_fd,
                uchar const keypair[64] ) {

  FILE * file = fdopen( key_fd, "w" );
  FD_TEST( file );

  FD_TEST( fwrite( "[", 1, 1, file )==1 );
  for( int i=0; i<63; i++ ) {
    FD_TEST( fprintf( file, "%d,", keypair[i] )>0 );
  }
  FD_TEST( fprintf( file, "%d]", keypair[63] )>0 );

  FD_TEST( 0==fclose( file ) );
}

/* Test keyload with a valid key file.  Closes key_fd. */

void
test_keyload_success( void ) {
  char key_path[] = "/tmp/test_keyload_XXXXXX";
  int key_fd = mkstemp( key_path );
  FD_TEST( key_fd>0 );

  uchar keypair[64] = {0};
  do {
    fd_sha512_t   _sha[1];
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
    fd_ed25519_public_from_private( keypair+32, keypair, sha );
    fd_sha512_delete( fd_sha512_leave( sha ) );
  } while(0);

  write_key_file( key_fd, keypair );
  key_fd = -1; /* closed */

  TEST_FORK_OK(
    uchar const * key = fd_keyload_load( key_path, 0 );
    FD_TEST( key );
    FD_TEST( 0==memcmp( key, keypair, 64 ) );
    fd_keyload_unload( key, 0 );
  );

  FD_TEST( 0==unlink( key_path ) );
}

/* test_keyload_bogus_pubkey: Ensure that keyload refuses to load key
   pairs where the public key doesn't match the private key. */

void
test_keyload_bogus_pubkey( void ) {
  char key_path[] = "/tmp/test_keyload_XXXXXX";
  int key_fd = mkstemp( key_path );
  FD_TEST( key_fd>0 );

  uchar keypair[64] = {0};
  do {
    fd_sha512_t   _sha[1];
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
    fd_ed25519_public_from_private( keypair+32, keypair, sha );
    fd_sha512_delete( fd_sha512_leave( sha ) );
  } while(0);
  keypair[63] ^= 1; /* flip a bit in the public key */

  write_key_file( key_fd, keypair );
  key_fd = -1; /* closed */

  pid_t pid = fork();
  FD_TEST( pid!=-1 );
  if( pid ) {
    int wstatus;
    FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );
    FD_TEST( wstatus==128+SIGABRT );
  } else {
    fd_keyload_load( key_path, 0 ); /* aborts */
    exit( 2 ); /* unreachable */
  }

  FD_TEST( 0==unlink( key_path ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_log_private_boot( &argc, &argv );
  test_protected_pages();
  test_keyload_success();
  test_keyload_bogus_pubkey();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
