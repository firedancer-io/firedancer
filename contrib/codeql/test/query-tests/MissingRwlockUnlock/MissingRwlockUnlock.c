#define __CODEQL_TEST__ 1

typedef struct { int value; } fd_rwlock_t;

void fd_rwlock_read   ( fd_rwlock_t * lock );
void fd_rwlock_write  ( fd_rwlock_t * lock );
void fd_rwlock_unread ( fd_rwlock_t * lock );
void fd_rwlock_unwrite( fd_rwlock_t * lock );
void fd_rwlock_demote ( fd_rwlock_t * lock );

int cond( void );

/* Leaks the lock on the early return. */

int
leak_early_return( fd_rwlock_t * lock ) {
  fd_rwlock_read( lock ); // $ Alert
  if( cond() ) return 1;
  fd_rwlock_unread( lock );
  return 0;
}

void
leak_fall_through( fd_rwlock_t * lock ) {
  fd_rwlock_write( lock ); // $ Alert
  if( cond() ) return;
  fd_rwlock_unwrite( lock );
}

void
leak_in_loop( fd_rwlock_t * lock ) {
  for( int i=0; i<10; i++ ) {
    fd_rwlock_read( lock ); // $ Alert
    if( cond() ) return;
    fd_rwlock_unread( lock );
  }
}

/* Releases the lock on every path. */

int
balanced( fd_rwlock_t * lock ) {
  fd_rwlock_read( lock );
  if( cond() ) {
    fd_rwlock_unread( lock );
    return 1;
  }
  fd_rwlock_unread( lock );
  return 0;
}

/* Acquire wrappers: every exit holds the lock and the caller releases
   it. */

void
acquire_wrapper( fd_rwlock_t * lock ) {
  fd_rwlock_write( lock );
}

int
acquire_wrapper_upgrade( fd_rwlock_t * lock,
                         int           write ) {
  if( !write ) {
    fd_rwlock_read( lock );
    if( cond() ) return 1;
    fd_rwlock_unread( lock );
  }
  fd_rwlock_write( lock );
  if( !write ) fd_rwlock_demote( lock );
  return 0;
}

int
acquire_wrapper_retry( fd_rwlock_t * lock ) {
  for(;;) {
    fd_rwlock_read( lock );
    if( cond() ) return 1;
    fd_rwlock_unread( lock );
  }
}
