#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h

/* fd_snapshot_restore.h provides APIs for restoring an execution
   context from the individual snapshot files.  (The outer layers, such
   as the TAR stream and Zstandard compression, are managed by
   fd_snapshot_load).

   The snapshot format contains complex data structures without size
   restrictions.  This API will effectively make an unbounded amount of
   heap allocations while loading a snapshot. */

#include "fd_snapshot_base.h"
#include "../../util/archive/fd_tar.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

/* fd_snapshot_restore_t implements a streaming TAR reader that parses
   archive records on the fly.  Records include the manifest (at the
   start of the file), and account data.  Notably, this object does on-
   the-fly heap allocations. */

struct fd_snapshot_restore;
typedef struct fd_snapshot_restore fd_snapshot_restore_t;

/* FD_SNAPSHOT_RESTORE_BUFSZ is the default read buffer size while
   loading data from a snapshot.  This is temporarily exceeded while
   loading the snapshot manifest. */

#define FD_SNAPSHOT_RESTORE_BUFSZ (1UL<<20)  /* 1 MiB */

/* fd_snapshot_restore_cb_manifest_fn_t is a callback that provides the
   user of snapshot restore with the deserialized manifest.  The caller
   may move out data from the manifest (by zeroing out the fields that
   data was moved out from).  The lifetime of these moved values is
   that of the memory allocator in fd_snapshot_restore_new.  Any
   leftover fields will be freed on return.  The caller is responsible
   for freeing any moved objects even when returning an error.

   ctx is the pointer provided to fd_snapshot_restore_set_cb_manifest.
   Returns 0 on success.  Non-zero return value implies failure.  The
   return value gets forwarded to the original caller of the restore
   API. */

typedef int
(* fd_snapshot_restore_cb_manifest_fn_t)( void *                 ctx,
                                          fd_solana_manifest_t * manifest );

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

   valloc is a memory allocator that outlives the snapshot restore
   object.  The restore object promises to not do more than valloc_max
   heap allocations (frees do not reset this number to also account for
   heap fragmentation).  valloc_max must be at least of size
   FD_SNAPSHOT_RESTORE_BUFSZ.  The recommended value for mainnet
   snapshots is 2 GiB as of 2024-02-05.  (But unfortunately, this
   continues to grow without bounds)

   The snapshot manifest is provided to the callback function.  This
   callback is invoked up to one time per restore object.  cb_ctx is an
   opaque pointer that is passed to the callback (and ignored by this
   API otherwise).  It is valid to provide a NULL cb_ctx.

   Accounts are restored into the given account manager and funk
   transaction.  (Note that the restore process will leave behind
   "tombstone" account records that are invisible to fd_acc_mgr_view,
   but do appear to fd_acc_mgr_view_raw.)

   On failure, returns NULL.  Reasons for failure include invalid memory
   region.  Logs reasons for failure. */

fd_snapshot_restore_t *
fd_snapshot_restore_new( void *                               mem,
                         fd_acc_mgr_t *                       acc_mgr,
                         fd_funk_txn_t *                      txn,
                         fd_valloc_t                          valloc,
                         void *                               cb_ctx,
                         fd_snapshot_restore_cb_manifest_fn_t cb );

/* fd_snapshot_restore_delete destroys the given restore object and
   frees any resources.  Returns main and scratch memory region back to
   caller. */

void *
fd_snapshot_restore_delete( fd_snapshot_restore_t * self );

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

/* fd_snapshot_restore_tar_vt implements fd_tar_read_vtable_t. */

extern fd_tar_read_vtable_t const fd_snapshot_restore_tar_vt;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h */
