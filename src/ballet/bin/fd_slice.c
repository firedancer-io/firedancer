#include "fd_slice.h"
#include <stdlib.h>

ulong
fd_slice_align( void ) {
  return FD_SLICE_ALIGN;
}

ulong
fd_slice_footprint( void ) {
  return FD_SLICE_FOOTPRINT;
}

fd_slice_t *
fd_slice_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL slice" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_slice_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned slice" ));
    return NULL;
  }

  fd_slice_t * slice = (fd_slice_t *)mem;

  memset( slice, 0, FD_SLICE_FOOTPRINT );

  return slice;
}

fd_slice_t *
fd_slice_join( fd_slice_t * slice,
               void *       mem,
               ulong        sz ) {

  if( FD_UNLIKELY( !slice ) ) {
    FD_LOG_WARNING(( "NULL slice" ));
    return NULL;
  }

  if( FD_UNLIKELY( (ulong)mem+sz < (ulong)mem ) ) {
    FD_LOG_WARNING(( "invalid memory range" ));
    return NULL;
  }

  slice->ptr   = mem;
  slice->end   = (void *)( (ulong)mem+sz );
  slice->flags = 0UL;

  return slice;
}

fd_slice_t *
fd_slice_clone( fd_slice_t * dst,
                fd_slice_t * src ) {
  memcpy( dst, src, FD_SLICE_FOOTPRINT );
  return dst;
}

fd_slice_t *
fd_slice_leave( fd_slice_t * slice ) {

  if( FD_UNLIKELY( !slice ) ) {
    FD_LOG_WARNING(( "NULL slice" ));
    return NULL;
  }

  memset( slice, 0, FD_SLICE_FOOTPRINT );
  return slice;
}

void *
fd_slice_delete( fd_slice_t * slice ) {

  if( FD_UNLIKELY( !slice ) ) {
    FD_LOG_WARNING(( "NULL slice" ));
    return NULL;
  }

  return (void *)slice;
}

fd_slice_t *
fd_slice_subslice( fd_slice_t * slice,
                   ulong        off,
                   ulong        sz ) {

  ulong const ptr     = (ulong)slice->ptr;
  ulong const end     = (ulong)slice->end;

  ulong const ptr_new = ptr     + off;
  ulong const end_new = ptr_new + sz;

  memset( slice, 0, FD_SLICE_FOOTPRINT );

  if( FD_UNLIKELY( off+sz<off || end_new<ptr || end_new>end ) ) {
    slice->flags = (1U<<FD_SLICE_FLAG_OOB);
    return NULL;
  }

  slice->ptr   = (void *)ptr_new;
  slice->end   = (void *)end_new;
  slice->flags = 0UL;

  return slice;
}

/* FIXME inline this? */
void *
fd_slice_advance( fd_slice_t * slice,
                  ulong        sz ) {

  ulong const ptr     = (ulong)slice->ptr;
  ulong const end     = (ulong)slice->end;

  ulong const ptr_new = ptr+sz;

  if( FD_UNLIKELY( ptr_new<ptr || ptr_new>end ) ) {
    slice->ptr   = (void *)end;
    slice->flags = (1U<<FD_SLICE_FLAG_OOB);
    return NULL;
  }

  slice->ptr = (void *)ptr_new;

  return (void *)ptr;
}
