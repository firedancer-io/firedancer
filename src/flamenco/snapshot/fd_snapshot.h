#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_h

#if FD_HAS_ZSTD

/* fd_snapshot.h provides high-level blocking APIs for Solana snapshots. */

#include "fd_snapshot_base.h"
#include "../runtime/fd_runtime_public.h"
#include "../../funk/fd_funk_txn.h"
#include "../../ballet/lthash/fd_lthash.h"

FD_PROTOTYPES_BEGIN

/* Whether to initialize these objects inside fd_snapshot_load_manifest_and_status_cache,
   or just advance the tar cursor. */
#define FD_SNAPSHOT_RESTORE_NONE         (0)
#define FD_SNAPSHOT_RESTORE_MANIFEST     (1)
#define FD_SNAPSHOT_RESTORE_STATUS_CACHE (2)

struct fd_snapshot_load_ctx;
typedef struct fd_snapshot_load_ctx fd_snapshot_load_ctx_t;

/* fd_snapshot_load_all does a blocking load of a snapshot. It is a wrapper
   around fd_snapshot_load_new, fd_snapshot_load_init,
   fd_snapshot_load_manifest_and_status_cache, and fd_snapshot_load_fini.

   fd_snapshot_load_new sets up the context that is passed around for the
   other fd_snapshot_load_* functions.

   fd_snapshot_load_init starts the process of loading in the snapshot and
   sets up the funk transactions, etc..

   fd_snapshot_load_manifest_and_status_cache loads in the manifest and the
   status cache exiting as soon as the manifest is loaded in.

   fd_snapshot_load_accounts will load in the rest of the snapshot file but
   the runtime is still not setup to run.

   fd_snapshot_load_fini will use the slot context and funk which are now
   populated to setup the runtime and finalize the snapshot load.

   The reason these are broken out is to support loading in the manifest as
   quickly as possible, allowing for other operations to start (like
   stake-weighted repair) while the rest of the snapshot is being loaded. This
   is needed as loading in the manifest only takes a few seconds and the overall
   time to load in a snapshot is dominated by loading in the append vecs.

   source_cstr is either a local file system path.
   TODO: Add support for an HTTP url.

   slot_ctx is a valid initialized slot context.

   spad should have enough space to buffer the snapshot's manifest.

   If verify_hash!=0 calculates the snapshot hash.

   If check_hash!=0 checks that the snapshot hash matches the file name.

   snapshot_type is one of FD_SNAPSHOT_TYPE_{...}. */

ulong
fd_snapshot_load_ctx_align( void );

ulong
fd_snapshot_load_ctx_footprint( void );

fd_snapshot_load_ctx_t *
fd_snapshot_load_new( uchar *                 mem,
                      const char *            snapshot_src,
                      int                     snapshot_src_type,
                      const char *            snapshot_dir,
                      fd_exec_slot_ctx_t *    slot_ctx,
                      uint                    verify_hash,
                      uint                    check_hash,
                      int                     snapshot_type,
                      fd_spad_t * *           exec_spads,
                      ulong                   spad_cnt,
                      fd_spad_t *             runtime_spad,
                      fd_exec_para_cb_ctx_t * exec_para_ctx );

void
fd_snapshot_load_init( fd_snapshot_load_ctx_t * ctx );

/* restore_manifest_flags controls if the manifest and status cache objects are initialized or not. */
void
fd_snapshot_load_manifest_and_status_cache( fd_snapshot_load_ctx_t * ctx,
                                            ulong *                  base_slot_override,
                                            int                      restore_manifest_flags );

void
fd_snapshot_load_accounts( fd_snapshot_load_ctx_t * ctx );

void
fd_snapshot_load_fini( fd_snapshot_load_ctx_t * ctx );

void
fd_snapshot_load_all( const char *         source_cstr,
                      int                  source_type,
                      const char *         snapshot_dir,
                      fd_exec_slot_ctx_t * slot_ctx,
                      ulong *              base_slot_override,
                      fd_tpool_t *         tpool,
                      uint                 verify_hash,
                      uint                 check_hash,
                      int                  snapshot_type,
                      fd_spad_t * *        exec_spads,
                      ulong                exec_spad_cnt,
                      fd_spad_t *          runtime_spad );

void
fd_snapshot_load_prefetch_manifest( fd_snapshot_load_ctx_t * ctx );

ulong
fd_snapshot_get_slot( fd_snapshot_load_ctx_t * ctx );

/* Generate a non-incremental hash of the entire account database, conditionally including in the epoch account hash. */
int
fd_snapshot_hash( fd_exec_slot_ctx_t *    slot_ctx,
                  fd_hash_t *             accounts_hash,
                  uint                    check_hash,
                  fd_spad_t *             runtime_spad,
                  fd_exec_para_cb_ctx_t * exec_para_ctx,
                  fd_lthash_value_t *     lt_hash );

/* Generate an incremental hash of the entire account database, conditionally including in the epoch account hash. */
int
fd_snapshot_inc_hash( fd_exec_slot_ctx_t * slot_ctx,
                      fd_hash_t *          accounts_hash,
                      fd_funk_txn_t *      child_txn,
                      uint                 check_hash,
                      fd_spad_t *          spad,
                      fd_lthash_value_t *  lt_hash );

FD_PROTOTYPES_END

#endif /* FD_HAS_ZSTD */

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_h */
