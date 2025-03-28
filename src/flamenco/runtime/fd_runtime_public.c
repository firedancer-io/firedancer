#include "fd_runtime_public.h"

ulong
fd_runtime_public_footprint( void ) {
  return sizeof(fd_runtime_public_t) +
         fd_spad_align() +
         fd_spad_footprint( FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT );
}

fd_runtime_public_t *
fd_runtime_public_join( void * shmem ) {
  fd_runtime_public_t * pub = (fd_runtime_public_t *)shmem;

  if( FD_UNLIKELY( pub->magic!=FD_RUNTIME_PUBLIC_MAGIC ) ) {
    FD_LOG_WARNING(( "Bad Magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( pub->runtime_spad_gaddr==0UL ) ) {
    FD_LOG_WARNING(( "Bad runtime spad allocation" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "No wksp containing shmem found" ));
    return NULL;
  }

  return pub;
}

void *
fd_runtime_public_new( void * shmem ) {
  fd_memset( shmem, 0, sizeof(fd_runtime_public_t) );

  fd_runtime_public_t * runtime_public = (fd_runtime_public_t *)shmem;

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "No wksp containing shmem found" ));
    return NULL;
  }

  runtime_public->magic = FD_RUNTIME_PUBLIC_MAGIC;

  /* The runtime_spad will in the contiguous region after the region's
     header. */
  uchar * spad_ptr = (uchar *)fd_ulong_align_up( (ulong)((uchar *)shmem + sizeof(fd_runtime_public_t)), fd_spad_align() );
  spad_ptr = fd_spad_new( spad_ptr, FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT );
  if( FD_UNLIKELY( !spad_ptr ) ) {
    FD_LOG_WARNING(( "Unable to create spad" ));
    return NULL;
  }

  runtime_public->runtime_spad_gaddr = fd_wksp_gaddr( wksp, spad_ptr );
  if( FD_UNLIKELY( !runtime_public->runtime_spad_gaddr ) ) {
    FD_LOG_WARNING(( "Unable to get runtime spad gaddr" ));
    return NULL;
  }

  return shmem;
}

fd_spad_t *
fd_runtime_public_join_and_get_runtime_spad( fd_runtime_public_t const * runtime_public ) {
  if( FD_UNLIKELY( !runtime_public ) )  {
    FD_LOG_WARNING(( "Invalid runtime_public" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( runtime_public );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "No wksp found" ));
    return NULL;
  }

  void * spad_laddr = fd_wksp_laddr( wksp, runtime_public->runtime_spad_gaddr );
  if( FD_UNLIKELY( !spad_laddr ) ) {
    FD_LOG_WARNING(( "Unable to get spad laddr" ));
    return NULL;
  }

  return fd_spad_join( spad_laddr );
}
