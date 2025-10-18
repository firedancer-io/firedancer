#include "fd_accdb_user.h"

fd_accdb_user_t *
fd_accdb_user_join( fd_accdb_user_t * ljoin,
                    void *            shfunk ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  memset( ljoin, 0, sizeof(fd_accdb_user_t) );
  if( FD_UNLIKELY( !fd_funk_join( ljoin->funk, shfunk ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join failed" ));
  }

  return ljoin;
}

void *
fd_accdb_user_leave( fd_accdb_user_t * user,
                      void **          opt_shfunk ) {
  if( FD_UNLIKELY( !user ) ) FD_LOG_CRIT(( "NULL ljoin" ));

  if( FD_UNLIKELY( !fd_funk_leave( user->funk, opt_shfunk ) ) ) FD_LOG_CRIT(( "fd_funk_leave failed" ));

  return user;
}
