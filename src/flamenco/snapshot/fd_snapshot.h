#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_h

#include "../fd_flamenco_base.h"
#include "../../util/archive/fd_tar.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

#if FD_HAS_ZSTD

/* Snapshot Create ****************************************************/

struct fd_snapshot_create_private;
typedef struct fd_snapshot_create_private fd_snapshot_create_t;

/* FD_SNAPSHOT_CREATE_{ALIGN,FOOTPRINT} are const-friendly versions
   of the memory region parameters for the fd_snapshot_create_t object. */

#define FD_SNAPSHOT_CREATE_ALIGN (32UL)

/* FD_SNAPSHOT_ACC_ALIGN is the alignment of an account header in an
   account vec / "AppendVec". */

#define FD_SNAPSHOT_ACC_ALIGN (8UL)

// FD_PROTOTYPES_BEGIN

/* fd_snapshot_create_{align,footprint} return required memory region
   parameters for the fd_snapshot_create_t object.

   worker_cnt is the number of workers for parallel snapshot create
   (treated as 1UL parallel mode not available). compress_lvl is the
   Zstandard compression level.  compress_bufsz is the in-memory buffer
   for writes (larger buffers results in less frequent but larger write
   ops).  funk_rec_cnt is the number of slots in the funk rec hashmap.
   batch_acc_cnt is the max number of accounts per account vec.

   Resulting footprint approximates

     O( funk_rec_cnt + (worker_cnt * (compress_lvl + compress_bufsz + batch_acc_cnt)) ) */

FD_FN_CONST ulong
fd_snapshot_create_align( void );

ulong
fd_snapshot_create_footprint( ulong worker_cnt,
                              int   compress_lvl,
                              ulong compress_bufsz,
                              ulong funk_rec_cnt,
                              ulong batch_acc_cnt );

/* fd_snapshot_create_new creates a new snapshot create object in the
   given mem region, which adheres to above alignment/footprint
   requirements.  Returns qualified handle to object given create object
   on success.  Serializes data from given slot context.  snap_path is
   the final snapshot path.  May create temporary files adject to
   snap_path.  {worker_cnt,compress_lvl,compress_bufsz,funk_rec_cnt,
   batch_acc_cnt} must match arguments to footprint when mem was
   created.  On failure, returns NULL. Reasons for failure include
   invalid memory region or invalid file descriptor.  Logs reasons for
   failure. */

fd_snapshot_create_t *
fd_snapshot_create_new( void *               mem,
                        fd_exec_slot_ctx_t * slot_ctx,
                        const char *         snap_path,
                        ulong                worker_cnt,
                        int                  compress_lvl,
                        ulong                compress_bufsz,
                        ulong                funk_rec_cnt,
                        ulong                batch_acc_cnt,
                        ulong                max_accv_sz,
                        fd_rng_t *           rng );

/* fd_snapshot_create_delete destroys the given snapshot create object
   and frees any resources.  Returns memory region and fd back to caller. */

void *
fd_snapshot_create_delete( fd_snapshot_create_t * create );

/* fd_snapshot_create exports the 'snapshot manifest' and a copy of all
   accounts from the slot ctx that the create object is attached to.
   Writes a .tar.zst stream out to the fd.  Returns 1 on success, and
   0 on failure.  Reason for failure is logged. */

int
fd_snapshot_create( fd_snapshot_create_t * create,
                    fd_exec_slot_ctx_t *   slot_ctx );

FD_PROTOTYPES_END

/* Snapshot Restore ***************************************************/

struct fd_snapshot_restore;
typedef struct fd_snapshot_restore fd_snapshot_restore_t;

/* FD_SNAPSHOT_RESTORE_SCRATCH_SZ is the size of the scratch memory
   required during fd_snapshot_restore. */

#define FD_SNAPSHOT_RESTORE_SCRATCH_SZ (1UL<<29)  /* 512 MiB */

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

#endif /* FD_HAS_ZSTD */

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_h */
