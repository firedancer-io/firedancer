#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h

/* fd_snapshot_restore.h provides APIs for restoring an execution
   context from the individual snapshot files.  (The outer layers, such
   as the TAR stream and Zstandard compression, are managed by
   fd_snapshot_load). */

#include "fd_snapshot_base.h"
#include "../../util/archive/fd_tar.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

struct fd_snapshot_restore;
typedef struct fd_snapshot_restore fd_snapshot_restore_t;

/* fd_snapshot_restore_cb_manifest_fn_t is a callback that provides the
   user of snapshot restore with the deserialized manifest.  The
   manifest is borrowed to the callee until it returns.  ctx is the
   pointer provided to fd_snapshot_restore_set_cb_manifest. */

typedef void
(* fd_snapshot_restore_cb_manifest_fn_t)( void *                 ctx,
                                          fd_solana_manifest_t * manifest );

/* FD_SNAPSHOT_RESTORE_SCRATCH_SZ is the size of the scratch memory
   required during fd_snapshot_restore. */

#define FD_SNAPSHOT_RESTORE_SCRATCH_SZ (1UL<<30)  /* 1 GiB */

FD_PROTOTYPES_BEGIN

/* fd_snapshot_restore_{align,footprint} return required memory region
   parameters for the fd_snapshot_restore_t object. */

FD_FN_CONST ulong
fd_snapshot_restore_align( void );

FD_FN_CONST ulong
fd_snapshot_restore_footprint( void );

/* fd_snapshot_restore_new creates a restore object in the given memory
   region, which adheres to above alignment/footprint requirements.
   Returns qualified handle to object given restore object on success.
   Attaches to given slot context, which outlives restore object.
   On failure, returns NULL.  Reasons for failure include invalid memory
   region.  Logs reasons for failure. */

fd_snapshot_restore_t *
fd_snapshot_restore_new( void *               mem,
                         fd_exec_slot_ctx_t * slot_ctx,
                         void *               scratch,
                         ulong                scratch_sz );

/* fd_snapshot_restore_delete destroys the given restore object and
   frees any resources.  Returns main and scratch memory region back to
   caller. */

void *
fd_snapshot_restore_delete( fd_snapshot_restore_t * self );

/* fd_snapshot_restore_set_cb_manifest sets the manifest callback.
   Gets invoked up to once in the lifetime of a snapshot restore. */

void
fd_snapshot_restore_set_cb_manifest( fd_snapshot_restore_t *              restore,
                                     fd_snapshot_restore_cb_manifest_fn_t cb,
                                     void *                               ctx );

/* fd_snapshot_restore_file provides a file to fd_snapshot_restore_t.
   restore is a fd_snapshot_restore_t pointer.  meta is the TAR file
   header of the file.  sz is the size of the file.  Suitable as a
   fd_tar_file_fn_t callback to fd_tar_reader. */

int
fd_snapshot_restore_file( void *                restore,
                          fd_tar_meta_t const * meta,
                          ulong                 sz );

/* fd_snapshot_restore_chunk provides a chunk of a file to
   fd_snapshot_restore_t.  restore is a fd_snapshot_restore_t pointer.
   [buf,buf+bufsz) is the memory region containing the file chunk.
   Suitable as a fd_tar_read_fn_t callback to fd_tar_reader. */

int
fd_snapshot_restore_chunk( void *       restore,
                           void const * buf,
                           ulong        bufsz );

/* fd_snapshot_restore is a convenience wrapper.  Returns 1 on success,
   and 0 on failure.  Logs reason for failure.  slot_ctx is the context
   into which snapshot should be restored.  path is file path of
   snapshot. valloc is used to allocate temporary memory (~1.3 GiB) */

int
fd_snapshot_restore( fd_exec_slot_ctx_t * slot_ctx,
                     char const *         path,
                     fd_valloc_t          valloc );

/* fd_snapshot_restore_tar_vt implements fd_tar_read_vtable_t. */

extern fd_tar_read_vtable_t const fd_snapshot_restore_tar_vt;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h */
