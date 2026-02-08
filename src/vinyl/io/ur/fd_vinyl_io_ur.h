#ifndef HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h
#define HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h

/* fd_vinyl_io_ur.h is a vinyl_io driver based on io_uring.  This is
   the fastest available driver and is recommended for production use.

   It consists of a fairly complex number of optimizations and is thus
   split into multiple modules:
   - fd_vinyl_io_ur_private.h: struct definitions
   - fd_vinyl_io_ur_rd.c: read path
   - fd_vinyl_io_ur_wb.c: write path (write back cache) */

#include "../fd_vinyl_io.h"
#include "../../../util/io_uring/fd_io_uring.h"

FD_PROTOTYPES_BEGIN

ulong
fd_vinyl_io_ur_align( void );

ulong
fd_vinyl_io_ur_footprint( ulong spad_max );

fd_vinyl_io_t *
fd_vinyl_io_ur_init( void *          mem,
                     ulong           spad_max,
                     int             dev_fd,
                     fd_io_uring_t * ring );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h */
