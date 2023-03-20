#ifndef HEADER_fd_src_util_bin_parse_fd_slice_h
#define HEADER_fd_src_util_bin_parse_fd_slice_h

#include "../fd_util.h"

struct fd_slice {
  uchar * cur;
  uchar * end;
};

typedef struct fd_slice fd_slice_t;

/* interface for the slice struct */

FD_PROTOTYPES_BEGIN

int
fd_slice_is_enough_space( fd_slice_t * slice,
                          ulong        sz     );

void fd_slice_increment_slice( fd_slice_t * slice,
                               ulong        size   );

/* read primitives */

int
fd_slice_read_u8( fd_slice_t  * slice,
                  uchar       * dest   );

int
fd_slice_read_u16( fd_slice_t * slice,
                   ushort     * dest   );

int
fd_slice_read_u32( fd_slice_t * slice,
                   uint       * dest   );

int
fd_slice_read_u64( fd_slice_t * slice,
                   ulong      * dest   );

int
fd_slice_read_blob_of_size( fd_slice_t * slice,
                            ulong        size,
                            void       * dest  );

int
fd_slice_peek_u32_at_offset( fd_slice_t * slice,
                             ulong        offset,
                             uint       * dest    );

/* write primitives */

int
fd_slice_write_u8( fd_slice_t * slice,
                   uchar        src );

int
fd_slice_write_u16( fd_slice_t * slice,
                    ushort       src );

int
fd_slice_write_u32( fd_slice_t * slice,
                    uint         src );

int
fd_slice_write_u64( fd_slice_t * slice,
                    ulong        src );

int
fd_slice_write_blob_of_size( fd_slice_t * slice,
                             void       * src,
                             ulong        size   );

FD_PROTOTYPES_END

#endif
