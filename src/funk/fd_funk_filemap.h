#ifndef HEADER_fd_src_funk_fd_funk_filemap_h
#define HEADER_fd_src_funk_fd_funk_filemap_h

#include "fd_funk.h"

enum fd_funk_file_mode {
  FD_FUNK_READONLY,    /* Only open the file if it already exists, memory is marked readonly */
  FD_FUNK_READ_WRITE,  /* Only open the file if it already exists, can be written to */
  FD_FUNK_CREATE,      /* Use an existing file if available, otherwise create */
  FD_FUNK_OVERWRITE,   /* Create new or overwrite existing with a fresh instance */
  FD_FUNK_CREATE_EXCL  /* Fail if file exists, only create new */
};
typedef enum fd_funk_file_mode fd_funk_file_mode_t;

struct fd_funk_close_file_args {
  void * shmem;
  int fd;
  ulong total_sz;
};
typedef struct fd_funk_close_file_args fd_funk_close_file_args_t;

fd_funk_t *
fd_funk_open_file( const char * filename,
                   ulong        wksp_tag,
                   ulong        seed,
                   ulong        txn_max,
                   ulong        rec_max,
                   ulong        total_sz,
                   fd_funk_file_mode_t mode,
                   fd_funk_close_file_args_t * close_args_out );

fd_funk_t *
fd_funk_recover_checkpoint( const char * funk_filename,
                            ulong        wksp_tag,
                            const char * checkpt_filename,
                            fd_funk_close_file_args_t * close_args_out );

void
fd_funk_close_file( fd_funk_close_file_args_t * close_args );

#endif /* HEADER_fd_src_funk_fd_funk_filemap_h */
