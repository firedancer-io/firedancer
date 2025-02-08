#include "fd_keyswitch.h"

FD_FN_CONST ulong
fd_keyswitch_align( void ) {
    return FD_KEYSWITCH_ALIGN;
}

FD_FN_CONST ulong
fd_keyswitch_footprint( void ) {
    return FD_KEYSWITCH_FOOTPRINT;
}

void *
fd_keyswitch_new( void * shmem,
                  ulong  state ) {
  fd_keyswitch_t * ks = (fd_keyswitch_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_keyswitch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_keyswitch_footprint();

  fd_memset( ks, 0, footprint );
  ks->state = state;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ks->magic ) = FD_KEYSWITCH_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ks;
}

fd_keyswitch_t *
fd_keyswitch_join( void * shks ) {

  if( FD_UNLIKELY( !shks ) ) {
    FD_LOG_WARNING(( "NULL shks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shks, fd_keyswitch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shks" ));
    return NULL;
  }

  fd_keyswitch_t * ks = (fd_keyswitch_t *)shks;

  if( FD_UNLIKELY( ks->magic!=FD_KEYSWITCH_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ks;
}

void *
fd_keyswitch_leave( fd_keyswitch_t const * ks ) {

  if( FD_UNLIKELY( !ks ) ) {
    FD_LOG_WARNING(( "NULL ks" ));
    return NULL;
  }

  return (void *)ks;
}

void *
fd_keyswitch_delete( void * shks ) {

  if( FD_UNLIKELY( !shks ) ) {
    FD_LOG_WARNING(( "NULL shks" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shks, fd_keyswitch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shks" ));
    return NULL;
  }

  fd_keyswitch_t * ks = (fd_keyswitch_t *)shks;

  if( FD_UNLIKELY( ks->magic!=FD_KEYSWITCH_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ks->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)ks;
}
