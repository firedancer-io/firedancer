#include "fd_runtime_public.h"

FD_FN_CONST ulong
fd_runtime_public_align( void ) {
  return fd_ulong_max( alignof(fd_runtime_public_t), fd_spad_align() );
}

ulong
fd_runtime_public_footprint( ulong spad_mem_max ) {
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
      alignof(fd_runtime_public_t), sizeof(fd_runtime_public_t) ),
      fd_spad_align(), fd_spad_footprint( spad_mem_max ) ),
      fd_runtime_public_align() );
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
fd_runtime_public_new( void * shmem,
                       ulong  spad_mem_max ) {
  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem is not part of a workspace" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_runtime_public_t * this     = FD_SCRATCH_ALLOC_APPEND( l, fd_runtime_public_align(), sizeof(fd_runtime_public_t) );
  void *                spad_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_spad_footprint( spad_mem_max ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_runtime_public_align() );

  fd_memset( this, 0, sizeof(fd_runtime_public_t) );

  if( FD_UNLIKELY( !fd_spad_new( spad_mem, spad_mem_max ) ) ) {
    FD_LOG_WARNING(( "Unable to create spad" ));
    return NULL;
  }

  this->runtime_spad_gaddr = fd_wksp_gaddr( wksp, spad_mem );
  if( FD_UNLIKELY( !this->runtime_spad_gaddr ) ) {
    FD_LOG_CRIT(( "fd_wksp_gaddr(%p) failed", spad_mem )); /* unreachable */
  }

  FD_COMPILER_MFENCE();
  this->magic = FD_RUNTIME_PUBLIC_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_spad_t *
fd_runtime_public_spad( fd_runtime_public_t const * runtime_public ) {
  if( FD_UNLIKELY( !runtime_public ) )  {
    FD_LOG_WARNING(( "NULL runtime_public" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( runtime_public );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "runtime_public is not part of a wksp" ));
    return NULL;
  }

  void * spad_laddr = fd_wksp_laddr( wksp, runtime_public->runtime_spad_gaddr );
  if( FD_UNLIKELY( !spad_laddr ) ) {
    FD_LOG_CRIT(( "fd_wksp_laddr(%p,0x%lx) failed", (void *)wksp, runtime_public->runtime_spad_gaddr )); /* unreachable */
    return NULL;
  }

  return fd_spad_join( spad_laddr );
}
