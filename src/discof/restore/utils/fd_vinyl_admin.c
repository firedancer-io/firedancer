#include "fd_vinyl_admin.h"

ulong
fd_vinyl_admin_align( void ) {
  return alignof(fd_vinyl_admin_t);
}

ulong
fd_vinyl_admin_footprint( void ){
  return sizeof(fd_vinyl_admin_t);
}

void *
fd_vinyl_admin_new( void * mem ) {
  fd_vinyl_admin_t * admin = (fd_vinyl_admin_t *)mem;

  memset( admin, 0UL, sizeof(fd_vinyl_admin_t) );

  admin->magic = FD_VINYL_ADMIN_MAGIC;

  fd_rwlock_new( &admin->lock );

  /* verbose initialization */
  admin->status = FD_VINYL_ADMIN_STATUS_INIT_PENDING;

  return (void *)admin;
}

fd_vinyl_admin_t *
fd_vinyl_admin_join( void * _admin ) {
  fd_vinyl_admin_t * admin = (fd_vinyl_admin_t *)_admin;
  if( FD_UNLIKELY( admin->magic!=FD_VINYL_ADMIN_MAGIC ) ) return NULL;
  return admin;
}

void *
fd_vinyl_admin_leave( fd_vinyl_admin_t * _admin ) {
  return (void *)_admin;
}

void *
fd_vinyl_admin_delete( void * _admin ) {
  return (void *)_admin;
}

ulong
fd_vinyl_admin_ulong_query( ulong const * _field ) {
  FD_COMPILER_MFENCE();
  ulong field = FD_VOLATILE_CONST( *_field );
  FD_COMPILER_MFENCE();
  return field;
}

void
fd_vinyl_admin_ulong_update( ulong * _field,
                             ulong   value ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *_field ) = value;
  FD_COMPILER_MFENCE();
}
