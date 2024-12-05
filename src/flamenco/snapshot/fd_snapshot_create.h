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

#define FD_BLOCKHASH_QUEUE_SIZE       (300UL)
#define FD_TICKS_PER_SLOT             (64UL)
/* This is the reasonably tight upper bound for the number of writable 
   accounts in a slot. This is because a block has a limit of 48 million
   compute units. Each writable account lock costs 300 CUs. That means there
   can be up to 48M/300 writable accounts in a block. */
#define FD_WRITABLE_ACCS_IN_SLOT      (160000UL)

#define FD_SNAPSHOT_DIR_MAX           (256UL)
#define FD_SNAPSHOT_VERSION_FILE      ("version")
#define FD_SNAPSHOT_VERSION           ("1.2.0")
#define FD_SNAPSHOT_VERSION_LEN       (5UL)
#define FD_SNAPSHOT_STATUS_CACHE_FILE ("snapshots/status_cache")

#define FD_SNAPSHOT_TMP_ARCHIVE           (".tmp.tar")
#define FD_SNAPSHOT_TMP_INCR_ARCHIVE      (".tmp_inc.tar")
#define FD_SNAPSHOT_TMP_FULL_ARCHIVE_ZSTD (".tmp.tar.zst")
#define FD_SNAPSHOT_TMP_INCR_ARCHIVE_ZSTD (".tmp_inc.tar.zst")

#define FD_SNAPSHOT_APPEND_VEC_SZ_MAX (16UL * 1024UL * 1024UL * 1024UL)

FD_PROTOTYPES_BEGIN

/* fd_snapshot_ctx_t holds various data structures needed for snapshot
   creation. It contains the snapshot slot, the snapshot directory,
   whether the snapshot is incremental, the tarball writer, the allocator,
   and holds the snapshot hash.
   
  NOTE: The snapshot service will currently not correctly free memory that is
        allocated unless a bump allocator like fd_scratch or fd_spad are used. */
struct fd_snapshot_ctx {
  ulong             slot;
  char const *      out_dir;
  fd_valloc_t       valloc;

  fd_tpool_t * tpool;

  uchar             is_incremental;
  ulong             last_snap_slot;
  ulong             last_snap_capitalization;
  fd_hash_t *       last_snap_hash;

  /* TODO: Add a comment here */
  int               tmp_fd;
  int               snapshot_fd;

  /* This gets setup within the context and not by the user */
  fd_tar_writer_t * writer;
  fd_hash_t         hash;
  fd_hash_t         acc_hash; /* incremental only */

  fd_slot_bank_t    slot_bank;
  fd_epoch_bank_t   epoch_bank;
  fd_acc_mgr_t *    acc_mgr;
  fd_txncache_t *   status_cache;

};
typedef struct fd_snapshot_ctx fd_snapshot_ctx_t;

/* fd_snapshot_create_populate_fseq, fd_snapshot_create_is_incremental, and
   fd_snapshot_create_get_slot are helpers used to pack and unpack the fseq
   used to indicate if a snapshot is ready to be created and if funk should be
   constipated. The other bytes represent the slot that the snapshot will be
   created for. */

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
      c. The manifest also contains other relevant metadata like the hashes
         of the accounts and the snapshot hash.
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

/* fd_snapshot_create_new_snapshot_offline is a strict superset of the 
   above function. It is repsonsible for managing the file descriptors
   used in snapshot creation. It should ONLY be used for creating
   snapshots for offline replay. The reason that file descriptors are
   not managed by the snapshot library for running a live node is to 
   maintain the sandbox. While running the full client, the file descriptors
   used by the snapshot service are maintained by the snapshot tile. */

int
fd_snapshot_create_new_snapshot_offline( fd_snapshot_ctx_t * snapshot_ctx,
                                         fd_hash_t *         out_hash,
                                         ulong *             out_capitalization );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_create_h */
