#ifndef HEADER_fd_src_funk_fd_funk_filemap_h
#define HEADER_fd_src_funk_fd_funk_filemap_h

#include "fd_funk.h"

enum fd_funk_file_mode {
  FD_FUNK_READONLY,		/* Only open the file if it already exists, memory is marked readonly */
  FD_FUNK_READ_WRITE,		/* Only open the file if it already exists, can be written to */
  FD_FUNK_CREATE_OR_REUSE,      /* Use an existing file if available, otherwise create */
  FD_FUNK_OVERWRITE,            /* Create new or overwrite existing with a fresh instance */
  FD_FUNK_CREATE_EXCL           /* Fail if file exists, only create new */
};
typedef enum fd_funk_file_mode fd_funk_file_mode_t;

fd_funk_t *
fd_funk_create_file( const char * filename,
                     ulong        wksp_tag,
                     ulong        seed,
                     ulong        txn_max,
                     ulong        rec_max,
                     ulong        total_sz,
                     fd_funk_file_mode_t mode );

#endif /* HEADER_fd_src_funk_fd_funk_filemap_h */
