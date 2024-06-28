#ifndef HEADER_fd_src_funk_fd_funk_archive_h
#define HEADER_fd_src_funk_fd_funk_archive_h

#include "fd_funk_rec.h"

/* This provides APIs for archiving funk. */

int fd_funk_archive( fd_funk_t *  funk,
                     char const * filename );

int fd_funk_unarchive( fd_funk_t *  funk,
                       char const * filename );

#endif /* HEADER_fd_src_funk_fd_funk_archive_h */
