#ifndef HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h
#define HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h

#include "fd_vinyl_io.h"

struct io_uring;

FD_PROTOTYPES_BEGIN

ulong
fd_vinyl_io_ur_align( void );

ulong
fd_vinyl_io_ur_footprint( void );

fd_vinyl_io_t *
fd_vinyl_io_ur_init( void *            mem,
                     int               dev_fd,
                     struct io_uring * ring );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vinyl_io_fd_vinyl_io_ur_h */
