#ifndef HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h
#define HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h

#include "fd_vinyl_io.h"
#include "../../util/io_uring/fd_io_uring.h"

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
