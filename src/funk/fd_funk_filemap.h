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

/* Open or create a funk instance with an optional mmap backing file.
   filename is the backing file, or NULL for a local/anonymous
   instance. wksp_tag is the workspace partition tag for funk (usually
   just 1). seed is the randomized hash seed. txn_max is the maximum
   number of funk transactions. rec_max is the maximum number of funk
   records. total_sz is the total size of the funk workspace. mode is
   the file mode (see above). close_args_opt is an optional pointer to a
   structure which is filled in. This is needed for fd_funk_close_file.

   Note that seed, txn_max, rec_max, and total_sz are ignored if
   an existing file is opened without being overwritten. */

fd_funk_t *
fd_funk_open_file( const char * filename,
                   ulong        wksp_tag,
                   ulong        seed,
                   ulong        txn_max,
                   ulong        rec_max,
                   ulong        total_sz,
                   fd_funk_file_mode_t mode,
                   fd_funk_close_file_args_t * close_args_out );

/* Load a workspace checkpoint containing a funk
   instance. funk_filename is the backing file, or NULL for a
   local/anonymous instance. wksp_tag is the workspace partition tag
   for funk (usually just 1). checkpt_filename is the checkpoint
   file. close_args_opt is an optional pointer to a structure which is
   filled in. This is needed for fd_funk_close_file. */

fd_funk_t *
fd_funk_recover_checkpoint( const char * funk_filename,
                            ulong        wksp_tag,
                            const char * checkpt_filename,
                            fd_funk_close_file_args_t * close_args_out );

/* Release the resources associated with a funk instance. The funk
   pointer is invalid after this is called. */

void
fd_funk_close_file( fd_funk_close_file_args_t * close_args );

#endif /* HEADER_fd_src_funk_fd_funk_filemap_h */
