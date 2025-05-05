#ifndef HEADER_fd_src_funk_fd_funk_filemap_h
#define HEADER_fd_src_funk_fd_funk_filemap_h

/* fd_funk_filemap.h provides an experimental API to access a funk DB
   via mmap(2) of a regular file.  Useful to test large funk DBs without
   much memory, but not suitable for production use. */

#include "fd_funk.h"

/* fd_funk_filemap_join_t describes a join to a file-backed funk
   instance. */

struct fd_funk_filemap_join {
  fd_funk_t funk[1];
  int       funk_fd;
  void *    map_start;
  ulong     map_size;
};

typedef struct fd_funk_filemap_join fd_funk_filemap_join_t;

/* Arguments for creating a funk filemap. */

struct fd_funk_filemap_create_args {
  ulong wksp_tag;   /* partition tag for workspace allocations (arbitrary, usually just 1) */
  ulong seed;       /* randomized funk hash seed */
  ulong txn_max;    /* maximum number of funk transactions */
  ulong rec_max;    /* maximum number of funk records */
  ulong total_sz;   /* ignored if restoring from a checkpoint */
  int   perm_bits;  /* third argument to open(2) */

  /* name of the temporary shm object to be registered via
     fd_shmem_join_anonymous */
  char  shmem_join_name[ FD_SHMEM_NAME_MAX ];
};

typedef struct fd_funk_filemap_create_args fd_funk_filemap_create_args_t;

FD_PROTOTYPES_BEGIN

/* fd_funk_filemap_create creates a funk instance backed by a file.
   file_path is the path to the file to create.  Returns 0 on success.
   On failure, returns an errno-compatible code and logs a warning.
   Reasons for failure include: file_path already exists, not enough
   space on file system, permission error, invalid (wksp_tag, txn_max,
   rec_max, total_sz). */

int
fd_funk_filemap_create( char const *                          file_path,
                        fd_funk_filemap_create_args_t const * args,
                        char const *                          shmem_join_name );

/* fd_funk_filemap_open joins a previously created file-backed funk
   instance using mmap(2).  file_path is the path of a funk workspace
   file previously created with fd_funk_filemap_create.  map_hint is
   passed as the first argument of mmap(2).  If read_write=={0,1}, the
   file and mapping is opened as {read-only,read-write}.  Returns ljoin
   populated with join info on success.  On failure, logs warning,
   returns NULL and leaves ljoin in an undefined state.  Reasons for
   failure include: error opening file, error mapping memory, corrupt
   workspace headers, or corrupt funk.

   Security: This API is not hardened against malicious funk instances.
   Attempting to access a corrupt funk file can result in memory
   corruption. */

fd_funk_filemap_join_t *
fd_funk_filemap_open( fd_funk_filemap_join_t * ljoin,
                      char const *             file_path,
                      void *                   map_hint,
                      int                      read_write );

/* Load a workspace checkpoint containing a funk
   instance. funk_filename is the backing file, or NULL for a
   local/anonymous instance. wksp_tag is the workspace partition tag
   for funk (usually just 1). checkpt_filename is the checkpoint
   file. close_args_opt is an optional pointer to a structure which is
   filled in. This is needed for fd_funk_close_file. */

int
fd_funk_recover_checkpoint( char const * funk_filename,
                            ulong        wksp_tag,
                            char const * checkpt_filename );

/* Release the resources associated with a funk file map. The funk
   pointer is invalid after this is called. */

void
fd_funk_filemap_close( fd_funk_filemap_join_t * close_args );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_filemap_h */
