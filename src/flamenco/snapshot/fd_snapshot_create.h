#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_create_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_create_h

/* fd_snapshot_create.h provides APIs for creating a Agave-compatible
   snapshot from a slot execution context. */

#include "fd_snapshot_base.h"
#include "../runtime/fd_runtime_init.h"
#include "../runtime/fd_txncache.h"
#include "../../util/archive/fd_tar.h"
#include "../types/fd_types.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

/* This is the reasonably tight upper bound for the number of writable 
   accounts in a slot. This is because a block has a limit of 48 million
   compute units. Each writable account lock costs 300 CUs. That means there
   can be up to 48M/300 writable accounts in a block. */
#define FD_WRITABLE_ACCS_IN_SLOT          (160000UL)
#define FD_BLOCKHASH_QUEUE_SIZE           (300UL)
#define FD_TICKS_PER_SLOT                 (64UL)

#define FD_SNAPSHOT_DIR_MAX               (256UL)
#define FD_SNAPSHOT_VERSION_FILE          ("version")
#define FD_SNAPSHOT_VERSION               ("1.2.0")
#define FD_SNAPSHOT_VERSION_LEN           (5UL)
#define FD_SNAPSHOT_STATUS_CACHE_FILE     ("snapshots/status_cache")

#define FD_SNAPSHOT_TMP_ARCHIVE           (".tmp.tar")
#define FD_SNAPSHOT_TMP_INCR_ARCHIVE      (".tmp_inc.tar")
#define FD_SNAPSHOT_TMP_FULL_ARCHIVE_ZSTD (".tmp.tar.zst")
#define FD_SNAPSHOT_TMP_INCR_ARCHIVE_ZSTD (".tmp_inc.tar.zst")

#define FD_SNAPSHOT_APPEND_VEC_SZ_MAX     (16UL * 1024UL * 1024UL * 1024UL) /* 16 MiB */

FD_PROTOTYPES_BEGIN

/* fd_snapshot_ctx_t holds various data structures needed for snapshot
   creation. It contains the snapshot slot, the snapshot directory,
   whether the snapshot is incremental, the tarball writer, the allocator,
   and holds the snapshot hash.
   
  FIXME: The snapshot service will currently not correctly free memory that is
         allocated unless a bump allocator like fd_scratch or fd_spad are used. */

struct fd_snapshot_ctx {

  /* These parameters are setup by the caller of the snapshot service. */
  ulong             slot;                      /* Slot for the snapshot. */
  char const *      out_dir;                   /* Output directory. */
  fd_valloc_t       valloc;                    /* Allocator */

  /* The two data structures from the runtime referenced by the snapshot service. */
  fd_funk_t *       funk;                      /* Funk handle. */
  fd_txncache_t *   status_cache;              /* Status cache handle. */

  uchar             is_incremental;            /* If it is incremental, set the fields and pass in data from the previous full snapshot. */
  ulong             last_snap_slot;            /* Full snapshot slot. */            
  ulong             last_snap_capitalization;  /* Full snapshot capitalization. */
  fd_hash_t *       last_snap_acc_hash;        /* Full snapshot account hash. */

  fd_tpool_t *      tpool;

  int               tmp_fd;
  int               snapshot_fd;

  /* This gets setup within the context and not by the user. */
  fd_tar_writer_t * writer;     /* Tar writer. */
  fd_hash_t         snap_hash;  /* Snapshot hash. */  
  fd_hash_t         acc_hash;   /* Account hash. */
  fd_slot_bank_t    slot_bank;  /* Obtained from funk. */
  fd_epoch_bank_t   epoch_bank; /* Obtained from funk. */
  fd_acc_mgr_t *    acc_mgr;    /* Wrapper for funk. */

};
typedef struct fd_snapshot_ctx fd_snapshot_ctx_t;

/* fd_snapshot_create_populate_fseq, fd_snapshot_create_is_incremental, and
   fd_snapshot_create_get_slot are helpers used to pack and unpack the fseq
   used to indicate if a snapshot is ready to be created and if the snapshot
   shoudl be incremental. The other bytes represent the slot that the snapshot
   will be created for. The most significant 8 bits determine if the snapshot
   is incremental and the least significant 56 bits are reserved for the slot.
   
   These functions are used for snapshot creation in the full client. */

static ulong FD_FN_UNUSED
fd_snapshot_create_pack_fseq( ulong is_incremental, ulong smr ) {
  return (is_incremental << 56UL) | (smr & 0xFFFFFFFFFFFFFFUL);
}

static ulong FD_FN_UNUSED
fd_snapshot_create_get_is_incremental( ulong fseq ) {
  return (fseq >> 56UL) & 0xFF;
}

static ulong FD_FN_UNUSED
fd_snapshot_create_get_slot( ulong fseq ) {
  return fseq & 0xFFFFFFFFFFFFFFUL;
}

/* fd_snapshot_create_new_snapshot is responsible for creating the different
   structures used for snapshot generation and outputting them to a servable,
   compressed tarball. The main components of a Solana snapshot are as follows:

   1. Version - This is a file that contains the version of the snapshot.
   2. Manifest - The manifest contains data about the state of the network
                 as well as the index of the append vecs. 
      a. The bank. This is the equivalent of the firedancer slot/epoch context.
         This contains almost all of the state of the network that is not
         encapsulated in the accounts.
      b. Append vec index. This is a list of all of the append vecs that are
         used to store the accounts. This is a slot indexed file.
      c. The manifest also contains other relevant metadata including the 
         account/snapshot hash.
   3. Status cache - the status cache holds the transaction statuses for the 
      last 300 rooted slots. This is a nested data structure which is indexed
      by blockhash. See fd_txncache.h for more details on the status cache.
   4. Accounts directory - the accounts directory contains the state of all
      of the accounts and is a set of files described by <slot#.id#>. These
      are described by the append vec index in the manifest.
      
  The files are written out into a tar archive which is then zstd compressed. 
  
  This can produce either a full snapshot or an incremental snapshot depending
  on the value of is_incremental. An incremental snapshot will contain all of 
  the information described above, except it will only contain accounts that
  have been modified or deleted since the creation of the last incremental
  snapshot. */

int
fd_snapshot_create_new_snapshot( fd_snapshot_ctx_t * snapshot_ctx,
                                 fd_hash_t *         out_hash,
                                 ulong *             out_capitalization );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_create_h */
