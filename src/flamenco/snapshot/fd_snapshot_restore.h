#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h

/* fd_snapshot_restore.h provides APIs for the downstream part of the
   snapshot loading pipeline.

     read => unzstd => untar => restore
                                ^^^^^^^

   This header provides APIs for restoring an execution context from the
   individual snapshot files.  (The outer layers, such as the TAR stream
   and Zstandard compression, are managed by fd_snapshot_load).

   The snapshot format contains complex data structures without size
   restrictions.  This API will effectively make an unbounded amount of
   heap allocations while loading a snapshot. */

#include "fd_snapshot_base.h"
#include "../../util/archive/fd_tar.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

/* We want to exit out of snapshot loading once the manifest has been loaded in.
   Once it has been seen, we don't want to exit out of snapshot loading if we
   have already done so once. We exit out to allow for manifest data to be used
   around the codebase. */

#define MANIFEST_DONE          (INT_MAX)
#define MANIFEST_DONE_NOT_SEEN (1)
#define MANIFEST_DONE_SEEN     (2)

/* fd_snapshot_restore_t implements a streaming TAR reader that parses
   archive records on the fly.  Records include the manifest (at the
   start of the file), and account data.  Notably, this object does on-
   the-fly heap allocations. */

struct fd_snapshot_restore;
typedef struct fd_snapshot_restore fd_snapshot_restore_t;

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
(* fd_snapshot_restore_cb_manifest_fn_t)( void *                              ctx,
                                          fd_solana_manifest_global_t const * manifest_global,
                                          fd_spad_t *                         spad );

/* fd_snapshot_restore_cb_status_cache_fn_t is a callback that provides the
   user of snapshot restore with the deserialized slot deltas.  The caller
   may copy data from the deltas. Any leftover fields will be freed on return.

   ctx is the pointer provided to fd_snapshot_restore_set_cb_status_cache.
   Returns 0 on success.  Non-zero return value implies failure.  The
   return value gets forwarded to the original caller of the restore
   API. */
typedef int
(* fd_snapshot_restore_cb_status_cache_fn_t)( void *                  ctx,
                                              fd_bank_slot_deltas_t * slot_deltas,
                                              fd_spad_t *             spad );
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

   spad is a bump allocator that outlives the snapshot restore
   object.  This allocator is used to buffer the serialized snapshot
   manifest (ca ~500 MB) and account data.

   The snapshot manifest is provided to the callback function.  This
   callback is invoked up to one time per restore object.  cb_manifest_ctx is an
   opaque pointer that is passed to the callback (and ignored by this
   API otherwise).  It is valid to provide a NULL cb_manifest_ctx.

   The status cache is also restored using the provided callback if
   a valid callback method is provided. It is valid to provide a NULL
   callback for testing purposes as of now, and the status_cache_ctx
   can also be NULL.

   Accounts are restored into the given account manager and funk
   transaction.  (Note that the restore process will leave behind
   "tombstone" account records that are invisible to fd_txn_account_init_from_funk_readonly,
   but do appear to fd_funk_get_acc_meta_readonly.)

   On failure, returns NULL.  Reasons for failure include invalid memory
   region.  Logs reasons for failure. */

fd_snapshot_restore_t *
fd_snapshot_restore_new( void *                                         mem,
                         fd_funk_t *                                    funk,
                         fd_funk_txn_t *                                txn,
                         fd_spad_t *                                    spad,
                         void *                                         cb_manifest_ctx,
                         fd_snapshot_restore_cb_manifest_fn_t           cb_manifest,
                         fd_snapshot_restore_cb_status_cache_fn_t       cb_status_cache );

/* fd_snapshot_restore_delete destroys the given restore object and
   frees any resources.  Returns allocated memory region back to
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

ulong
fd_snapshot_restore_get_slot( fd_snapshot_restore_t * restore );

extern fd_tar_read_vtable_t const fd_snapshot_restore_tar_vt;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_restore_h */
