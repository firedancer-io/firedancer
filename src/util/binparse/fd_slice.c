#include "fd_slice.h"
#include <stdlib.h>

/* primitives for using the slice abstraction, with bounds checking */

int
fd_slice_read_u8( fd_slice_t  * slice,
                  uchar       * dest   ) {
                    
  if( FD_UNLIKELY( slice->cur+1>slice->end ) ) {
    return 0;
  }

  *dest = *slice->cur;
  slice->cur++;
  return 1;
}

int
fd_slice_read_u16( fd_slice_t * slice,
                   ushort     * dest ) {
  if( FD_UNLIKELY( slice->cur+2>slice->end ) ) {
    return 0;
  }

  *dest = *(ushort *)slice->cur;
  slice->cur+=2;
  return 1;
}

int
fd_slice_is_enough_space( fd_slice_t * slice,
                          ulong        sz     ) {
  if( FD_UNLIKELY( (ulong)( slice->end - slice->cur )>=sz ) ) {
    return 1;
  } else {
    return 0;
  }
}

int
fd_slice_read_u32( fd_slice_t * slice,
                   uint       * dest   ) {
  if( FD_UNLIKELY( slice->cur+4>slice->end ) ) {
    return 0;
  }

  *dest = *(uint *)slice->cur;
  slice->cur+=4;
  return 1;
}

int
fd_slice_peek_u32_at_offset( fd_slice_t * slice,
                             ulong        offset,
                             uint       * dest    ) {
  if( FD_UNLIKELY( slice->cur+offset+4>slice->end ) ) {
    return 0;
  }

  *dest = *(uint *)(slice->cur+offset);
  return 1;
}

int
fd_slice_read_u64( fd_slice_t * slice,
                   ulong      * dest ) {
  if( FD_UNLIKELY( slice->cur+8>slice->end ) ) {
    return 0;
  }

  *dest = *(ulong *)slice->cur;
  slice->cur+=8;
  return 1;
}

void fd_slice_increment_slice( fd_slice_t * slice,
                               ulong        size   ) {
  slice->cur += size;
}

int
fd_slice_read_blob_of_size( fd_slice_t * slice,
                            ulong        size,
                            void       * dest   ) {
  if( ( FD_UNLIKELY( slice->cur+size>slice->end ) ) ) {
    FD_LOG_WARNING(( " slice->cur + size > slice->end " ));
    return 0;
  }

  fd_memcpy( dest, slice->cur, size );
  slice->cur+=size;
  return 1;
}

int
fd_slice_write_u8( fd_slice_t * slice,
                   uchar        src ) {
  if( FD_UNLIKELY( slice->cur+1>slice->end ) ) {
    return 0;
  }

  uchar * dest = (uchar *)slice->cur;
  *dest = src;
  slice->cur+=1;
  return 1;
}

int
fd_slice_write_u16( fd_slice_t * slice,
                    ushort       src ) {
  if( FD_UNLIKELY( slice->cur+2>slice->end ) ) {
    return 0;
  }

  ushort * dest = (ushort *)slice->cur;
  *dest = src;
  slice->cur+=2;
  return 1;
}

int
fd_slice_write_u32( fd_slice_t * slice,
                    uint         src ) {
  if( FD_UNLIKELY( slice->cur+4>slice->end ) ) {
    return 0;
  }

  uint * dest = (uint *)slice->cur;
  *dest = src;
  slice->cur+=4;
  return 1;
}

int
fd_slice_write_u64( fd_slice_t * slice,
                    ulong        src ) {
  if( FD_UNLIKELY( slice->cur+8>slice->end ) ) {
    return 0;
  }

  ulong * dest = (ulong *)slice->cur;
  *dest = src;
  slice->cur+=8;
  return 1;
}

int
fd_slice_write_blob_of_size( fd_slice_t * slice,
                             void       * src,
                             ulong        size   ) {
  if( ( FD_UNLIKELY( slice->cur+size>slice->end ) ) ) {
    FD_LOG_WARNING(( " slice->cur + size > slice->end " ));
    return 0;
  }

  fd_memcpy( slice->cur, src, size );
  slice->cur+=size;
  return 1;
}


