#include "../util/fd_util.h"
#include "fd_rwlock.h"

/* Basic single-threaded correctness tests for fd_rwlock. */

static void
test_rwlock_new( void ) {
  fd_rwlock_t lock[1];
  FD_TEST( fd_rwlock_new( lock ) );
  FD_TEST( atomic_load( &lock->value )==0 );
}

static void
test_rwlock_write_unwrite( void ) {
  fd_rwlock_t lock[1];
  fd_rwlock_new( lock );

  fd_rwlock_write( lock );
  FD_TEST( atomic_load( &lock->value )==FD_RWLOCK_WRITE_LOCK );

  fd_rwlock_unwrite( lock );
  FD_TEST( atomic_load( &lock->value )==0 );
}

static void
test_rwlock_read_unread( void ) {
  fd_rwlock_t lock[1];
  fd_rwlock_new( lock );

  fd_rwlock_read( lock );
  FD_TEST( atomic_load( &lock->value )==1 );

  fd_rwlock_read( lock );
  FD_TEST( atomic_load( &lock->value )==2 );

  fd_rwlock_read( lock );
  FD_TEST( atomic_load( &lock->value )==3 );

  fd_rwlock_unread( lock );
  FD_TEST( atomic_load( &lock->value )==2 );

  fd_rwlock_unread( lock );
  FD_TEST( atomic_load( &lock->value )==1 );

  fd_rwlock_unread( lock );
  FD_TEST( atomic_load( &lock->value )==0 );
}

static void
test_rwlock_demote( void ) {
  fd_rwlock_t lock[1];
  fd_rwlock_new( lock );

  fd_rwlock_write( lock );
  FD_TEST( atomic_load( &lock->value )==FD_RWLOCK_WRITE_LOCK );

  fd_rwlock_demote( lock );
  FD_TEST( atomic_load( &lock->value )==1 );

  /* Should be able to acquire another read lock now */
  fd_rwlock_read( lock );
  FD_TEST( atomic_load( &lock->value )==2 );

  fd_rwlock_unread( lock );
  fd_rwlock_unread( lock );
  FD_TEST( atomic_load( &lock->value )==0 );
}

static void
test_rwlock_trywrite( void ) {
  fd_rwlock_t lock[1];
  fd_rwlock_new( lock );

  /* trywrite on unlocked should succeed */
  FD_TEST( fd_rwlock_trywrite( lock )==1 );
  FD_TEST( atomic_load( &lock->value )==FD_RWLOCK_WRITE_LOCK );

  /* trywrite on write-locked should fail */
  FD_TEST( fd_rwlock_trywrite( lock )==0 );

  fd_rwlock_unwrite( lock );

  /* trywrite after unlock should succeed again */
  FD_TEST( fd_rwlock_trywrite( lock )==1 );
  fd_rwlock_unwrite( lock );
}

static void
test_rwlock_tryread( void ) {
  fd_rwlock_t lock[1];
  fd_rwlock_new( lock );

  /* tryread on unlocked should succeed */
  FD_TEST( fd_rwlock_tryread( lock )==1 );
  FD_TEST( atomic_load( &lock->value )==1 );

  /* tryread again should succeed (multiple readers) */
  FD_TEST( fd_rwlock_tryread( lock )==1 );
  FD_TEST( atomic_load( &lock->value )==2 );

  fd_rwlock_unread( lock );
  fd_rwlock_unread( lock );

  /* tryread on write-locked should fail */
  fd_rwlock_write( lock );
  FD_TEST( fd_rwlock_tryread( lock )==0 );
  fd_rwlock_unwrite( lock );
}

static void
test_rwlock_trywrite_while_read( void ) {
  fd_rwlock_t lock[1];
  fd_rwlock_new( lock );

  fd_rwlock_read( lock );
  FD_TEST( fd_rwlock_trywrite( lock )==0 );
  fd_rwlock_unread( lock );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_rwlock_new();
  test_rwlock_write_unwrite();
  test_rwlock_read_unread();
  test_rwlock_demote();
  test_rwlock_trywrite();
  test_rwlock_tryread();
  test_rwlock_trywrite_while_read();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
